package controller

import (
	"bubble/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

/*
 url     --> controller  --> logic   -->    model
请求来了  -->  控制器      --> 业务逻辑  --> 模型层的增删改查
*/

// jwt密钥
var secretKey = "riverk"

func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

// SignUp 处理用户注册函数
//
// @Summary 用户注册
// @Description 用户使用提供的 JSON 数据进行注册，成功则返回用户信息。
// @ID signup
// @Accept json
// @Produce json
// @Tags Start
// @Param user body models.User true "包含用户名和密码的 JSON 对象"
// @Success 201 {object} models.SuccessResponse "注册成功的响应"
// @Failure 400 {object} models.ErrorResponse "无效的 JSON 数据"
// @Failure 409 {object} models.ErrorResponse "用户名或密码已存在的错误响应"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误的错误响应"
// @Router /signup [post]
func SignUp(c *gin.Context) {
	var user models.User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	existingUser, _ := models.GetUserName(user.Username)
	if existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Invalid Username or Password"})
		return
	}
	// 生成4位随机数作为 UID
	user.UID = generateUniqueUID()
	// 用户不存在，hash存库
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	user.Password = string(hashedPassword)
	// 注册逻辑：尝试插入数据库，如果唯一性冲突，则重新生成 UID
	if err := models.CreateAUser(&user); err != nil {
		// 检查错误是否是唯一性冲突
		if strings.Contains(err.Error(), "unique constraint") {
			// 重新生成 UID
			user.UID = generateUniqueUID()
			// 重新尝试插入
			if err := models.CreateAUser(&user); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"msg":  "signup success",
		"data": user,
	})
}

// 生成4位随机数作为用户uid
func generateUniqueUID() uint {
	return uint(rand.Intn(10000))
}

// LoginHandler 处理用户登录函数
//
// @Summary 用户登录
// @Description 用户使用提供的 JSON 数据进行登录，验证用户名和密码，成功则生成带有用户信息的 JWT Token。
// @ID login
// @Accept json
// @Produce json
// @Tags Start
// @Param user body models.User true "包含用户名和密码的 JSON 对象"
// @Success 200 {object} models.SuccessResponse "成功登录的响应"
// @Failure 400 {object} models.ErrorResponse "无效的 JSON 数据"
// @Failure 401 {object} models.ErrorResponse "用户名或密码错误的错误响应"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误的错误响应"
// @Router /login [post]
func LoginHandler(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	//验证是否存在该用户
	existingUser, _ := models.GetUserName(user.Username)
	if existingUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Username or Password"})
		return
	}
	//存在该用户，进行密码匹配
	err := bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(user.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Username or Password"})
		return
	}
	// 验证成功，使用jwt中间件生成有效期为1小时的token
	expirationTime := time.Now().Add(1 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":      existingUser.UID,
		"username": existingUser.Username,
		"exp":      expirationTime.Unix(),
	})
	signedString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// 登录成功，将 token 发送给前端
	c.JSON(http.StatusOK, gin.H{
		"msg":   "signin success",
		"token": signedString,
		"data": gin.H{
			"username": existingUser.Username,
			"uid":      existingUser.UID,
		},
	})

}

// SignOut 处理用户登出的函数。
//
// @Summary 用户登出
// @Description 根据请求中的令牌，将用户标记为登出状态，并加入黑名单。
// @ID sign-out
// @Accept json
// @Produce json
// @Tags Start
// @Param token header string true "用户身份令牌"
// @Success 200 {object} models.SuccessResponse "成功登出"
// @Failure 400 {object} models.ErrorResponse "未提供令牌"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误"
// @Router /signout [post]
func SignOut(c *gin.Context) {
	// 获取令牌，例如从请求头中提取
	token := c.GetHeader("token")

	// 将令牌添加到黑名单
	err := AddTokenToBlacklist(token)
	if err != nil {
		// 处理错误，例如返回错误响应
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign out"})
		return
	}
	//// 记录一条日志，表示令牌已成功添加到黑名单
	//log.Printf("Token added to blacklist: %s\n", token)
	// 返回成功响应
	c.JSON(http.StatusOK, gin.H{"msg": "Successfully signed out"})
}

// AddTokenToBlacklist 将令牌加入数据库，并立即标记为过期
func AddTokenToBlacklist(token string) error {
	// 解析令牌以验证其有效性
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		return err
	}
	// 使用当前时间作为过期时间，即立即过期
	expiryTime := time.Now()
	blacklistedToken := models.BlacklistedToken{
		Token:      token,
		ExpiryTime: expiryTime,
	}
	if err := models.CreateBlackToken(&blacklistedToken); err != nil {
		return err
	}
	return nil
}

// CleanUpExpiredTokens 清理过期令牌
func CleanUpExpiredTokens() {
	logrus.Info("Starting token cleanup routine...")
	ticker := time.NewTicker(24 * time.Hour)
	for {
		select {
		case <-ticker.C:
			logrus.Info("Cleaning up expired tokens...")
			deletedTokens, err := models.DeleteGetBlackToken()
			if err != nil {
				logrus.Error("Error cleaning up expired tokens:", err)
			} else {
				logrus.Infof("Expired tokens cleaned up successfully, %d tokens removed", deletedTokens)
			}
		}
	}
}

// AuthenticationMiddleware jwt中间件验证
func AuthenticationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("token")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header not provided",
			})
			c.Abort()
			return
		}
		// 检查令牌是否在数据库中
		found, _ := models.GetBlackToken(tokenString)
		if found {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has been invalidated"})
			c.Abort()
			return
		}
		// 检查token是否有效
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		// 检查过期时间
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			expTime := int64(claims["exp"].(float64))
			if time.Now().Unix() > expTime {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
				c.Abort()
				return
			}
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}
		// 将用户信息设置到上下文中
		claims := token.Claims.(jwt.MapClaims)
		c.Set("uid", int(claims["uid"].(float64)))
		//fmt.Println("uid", int(claims["uid"].(float64)))
		c.Next()
	}
}

// CreateTodo 处理创建待办事项的函数。
//
// @Summary 创建待办事项
// @Description 接收前端页面提交的待办事项数据，并将其存储到数据库中。
// @ID create-todo
// @Accept json
// @Produce json
// @Tags Todo
// @Param token header string true "用户身份令牌"
// @Param todo body models.Todo true "待办事项的详细信息"
// @Success 201 {object} models.SuccessResponse "成功创建待办事项"
// @Failure 400 {object} models.ErrorResponse "请求中包含无效的 JSON 数据"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误"
// @Router /todo [post]
func CreateTodo(c *gin.Context) {
	// 前端页面填写待办事项 点击提交 会发请求到这里
	// 1. 从请求中把数据拿出来
	var todo models.Todo
	if err := c.BindJSON(&todo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	if todo.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Title field cannot be empty"})
		return
	}
	todo.UID = uint(c.GetInt("uid"))
	// 2. 存入数据库
	err := models.CreateATodo(&todo)
	if err != nil {
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"msg":  "Create Success",
		"data": todo,
	})
}

// GetTodoList 获取所有待办事项列表的函数。
//
// @Summary 获取所有待办事项
// @Description 查询 todo 表中的所有数据，并返回待办事项列表。
// @ID get-todo-list
// @Produce json
// @Tags Todo
// @Param token header string true "用户身份令牌"
// @Success 200 {object} models.SuccessResponse "成功获取待办事项列表"
// @Failure 400 {object} models.ErrorResponse "无效的请求"
// @Router /todo [get]
func GetTodoList(c *gin.Context) {
	// 查询todo这个表里的所有数据
	todoList, err := models.GetAllTodo()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	} else {
		c.JSON(http.StatusOK, gin.H{
			"msg":  "success",
			"data": todoList,
		})
	}
}

// GetTodo 根据用户ID获取特定用户的待办事项列表的函数。
//
// @Summary 获取特定用户的待办事项列表
// @Description 根据用户ID查询特定用户的待办事项，并返回待办事项列表。
// @ID get-todo
// @Produce json
// @Tags Todo
// @Param uid path int true "用户UID"
// @Param token header string true "用户身份令牌"
// @Success 200 {object} models.SuccessResponse "成功获取待办事项列表"
// @Failure 400 {object} models.ErrorResponse "无效的ID"
// @Failure 404 {object} models.ErrorResponse "未找到匹配记录"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误"
// @Router /todo/{uid} [get]
func GetTodo(c *gin.Context) {
	uid, err := strconv.ParseInt(c.Param("uid"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	todos, err := models.GetATodoUid(int(uid))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	//返回的切片是空判断没有该uid的todos
	if len(todos) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching records found"})
		return
	}
	c.JSON(http.StatusOK, todos)
}

// UpdateATodo 更新特定待办事项的函数。
//
// @Summary 更新待办事项
// @Description 根据待办事项ID更新待办事项记录，并返回更新后的待办事项信息。
// @ID update-todo
// @Accept json
// @Produce json
// @Tags Todo
// @Param token header string true "用户身份令牌"
// @Param id path int true "待办事项ID"
// @Param update body models.Todo true "待办事项的更新信息"
// @Success 200 {object} models.SuccessResponse "成功更新待办事项"
// @Failure 400 {object} models.ErrorResponse "无效的ID或JSON数据"
// @Failure 404 {object} models.ErrorResponse "未找到匹配记录"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误"
// @Router /todo/{id} [put]
func UpdateATodo(c *gin.Context) {
	var update models.Todo
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 绑定 JSON 数据
	if err := c.BindJSON(&update); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	// 查找待更新的Todo记录
	err = models.UpdateATodo(&id, &update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid ID"})
		return
	}
	responseData := gin.H{
		"msg":  "Update success",
		"data": gin.H{},
	}
	if update.Title != "" { // 只有当title有值时，我们才加入到响应中
		responseData["data"].(gin.H)["title"] = update.Title
	}
	if update.Status != nil { // 只有当title有值时，我们才加入到响应中
		responseData["data"].(gin.H)["status"] = update.Status
	}
	c.JSON(http.StatusOK, responseData)
}

// DeleteATodo 删除特定待办事项的函数。
//
// @Summary 删除待办事项
// @Description 根据待办事项ID删除待办事项记录。
// @ID delete-todo
// @Produce json
// @Tags Todo
// @Param token header string true "用户身份令牌"
// @Param id path int true "待办事项ID"
// @Success 200 {object} models.SuccessResponse "成功删除待办事项"
// @Failure 400 {object} models.ErrorResponse "无效的ID"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误"
// @Router /todo/{id} [delete]
func DeleteATodo(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err = models.DeleteATodo(&id)
	if err != nil {
		// 处理删除操作出现的错误
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "Todo deleted"})
}

/*

	用户相关操作

*/
// @Summary 获取所有用户列表
// @Description 查询所有用户并返回用户列表。
// @ID get-user-list
// @Produce json
// @Tags User
// @Param token header string true "用户身份令牌"
// @Success 200 {object} models.SuccessResponse "成功获取用户列表"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误"
// @Router /user/list [get]
func GetUserList(c *gin.Context) {
	userList, err := models.GetAllUser()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"data": userList,
			"msg":  "success",
		})
	}
}

// @Summary 获取特定用户信息
// @Description 根据用户ID查询特定用户信息，并返回用户信息。
// @ID get-user
// @Produce json
// @Tags User
// @Param uid path int true "用户ID"
// @Param token header string true "用户身份令牌"
// @Success 200 {object} models.SuccessResponse "成功获取特定用户信息"
// @Failure 400 {object} models.ErrorResponse "无效的UID"
// @Failure 404 {object} models.ErrorResponse "未找到匹配记录"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误"
// @Router /user/{uid} [get]
func GetUser(c *gin.Context) {
	uid, err := strconv.ParseInt(c.Param("uid"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid UID"})
		return
	}
	users, err := models.GetUserUid(int(uid))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(users) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching records found"})
		return
	}
	c.JSON(http.StatusOK, users)
}

// @Summary 更新特定用户信息
// @Description 根据用户ID更新用户信息，并返回更新后的用户信息。
// @ID update-user
// @Accept json
// @Produce json
// @Tags User
// @Param uid path int true "用户ID"
// @Param token header string true "用户身份令牌"
// @Param update body models.User true "用户的更新信息"
// @Success 200 {object} models.SuccessResponse "成功更新特定用户信息"
// @Failure 400 {object} models.ErrorResponse "无效的UID或JSON数据"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误"
// @Router /user/{uid} [put]
func UpdateAUser(c *gin.Context) {
	var Updateuser models.User
	uid, err := strconv.Atoi(c.Param("uid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err = c.BindJSON(&Updateuser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 在这里对密码进行加密
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(Updateuser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt password"})
		return
	}
	// 更新用户结构体中的密码为加密后的值
	Updateuser.Password = string(hashedPassword)
	// 执行更新用户操作(包含了检查用户是否处于删除状态)
	if err := models.UpdateAUser(&uid, &Updateuser); err != nil {
		// 在这里处理更新失败的逻辑，比如数据库错误等
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"msg": "update success",
		"data": gin.H{
			"username": Updateuser.Username,
			"password": "********", // 不返回实际密码，用占位符表示
		},
	})
}

// @Summary 删除特定用户
// @Description 根据用户ID删除用户记录。
// @ID delete-user
// @Produce json
// @Tags User
// @Param token header string true "用户身份令牌"
// @Param uid path int true "用户ID"
// @Success 200 {object} models.SuccessResponse "成功删除特定用户"
// @Failure 400 {object} models.ErrorResponse "无效的UID"
// @Failure 500 {object} models.ErrorResponse "服务器内部错误"
// @Router /user/{uid} [delete]
func DeleteAUser(c *gin.Context) {
	uid, err := strconv.ParseInt(c.Param("uid"), 10, 64)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 验证用户是否存在且删除
	if err := models.DeleteAUser(int(uid)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "User deleted"})
}
