package models

import (
	"bubble/dao"
	"errors"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"time"
)

type Todo struct {
	gorm.Model
	UID    uint   `json:"uid"`
	Title  string `json:"title"`
	Status *bool  `json:"status,omitempty"`
}

type User struct {
	gorm.Model
	UID      uint   `json:"uid" gorm:"uniqueIndex"`
	Username string `json:"username" gorm:"unique"`
	Password string `json:"password"`
}

type BlacklistedToken struct {
	gorm.Model
	Token      string    `gorm:"unique;not null"`
	ExpiryTime time.Time `gorm:"not null"`
}

// ErrorResponse 表示错误响应的模型。
type ErrorResponse struct {
	Error interface{} `json:"error"`
}

// SuccessResponse  表示成功响应的模型。
type SuccessResponse struct {
	Msg  string `json:"msg"`
	Data string `json:"data"`
	//Token string `json:"token"`
}

/*
	BlacklistedToken这个Model的增删改查操作都放在这里


*/
// CreateBlackToken 创建BlacklistedToken
func CreateBlackToken(bt *BlacklistedToken) (err error) {
	if err := dao.DB.Create(bt).Error; err != nil {
		// 检查错误是否是插入成功
		return fmt.Errorf("failed to create token: %w", err)
	}
	// 插入成功，没有错误
	return nil
}

func GetBlackToken(bt string) (bool, error) {
	token := new(BlacklistedToken)
	if err := dao.DB.Where("token = ?", bt).First(token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 未找到匹配记录，令牌不在黑名单中
			return false, nil
		}
		return false, err
	}
	// 找到匹配记录，令牌在黑名单中
	return true, nil
}

func DeleteGetBlackToken() (int64, error) {
	logrus.Info("Deleting expired black tokens...")

	// 查询过期的令牌记录
	var expiredTokens []BlacklistedToken
	err := dao.DB.Where("expiry_time < ?", time.Now()).Find(&expiredTokens).Error
	if err != nil {
		logrus.Error("Error querying expired black tokens:", err)
		return 0, err
	}

	// 打印查询到的过期令牌
	//logrus.Infof("Found %d expired black tokens", len(expiredTokens))
	//for _, token := range expiredTokens {
	//	logrus.Infof("Expired token: %s, expiry time: %v", token.Token, token.ExpiryTime)
	//}
	// 删除过期的令牌记录
	db := dao.DB.Where("expiry_time < ?", time.Now()).Delete(&BlacklistedToken{})
	if err := db.Error; err != nil {
		logrus.Error("Error deleting expired black tokens:", err)
		return 0, err
	}
	return db.RowsAffected, nil
}

/*
	Todo这个Model的增删改查操作都放在这里


*/
// CreateATodo 创建todo
func CreateATodo(todo *Todo) (err error) {
	if err := dao.DB.Create(&todo).Error; err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}
	return nil
}

func GetAllTodo() (todoList []*Todo, err error) {
	if err = dao.DB.Find(&todoList).Error; err != nil {
		return nil, err
	}
	return
}

func GetATodoUid(uid int) ([]*Todo, error) {
	var todos []*Todo
	if err := dao.DB.Where("uid = ?", uid).Find(&todos).Error; err != nil {
		return nil, fmt.Errorf("failed to get todos for uid %d: %v", uid, err)
	}
	return todos, nil
}

func UpdateATodo(id *int, todo *Todo) (err error) {
	var existingTodo Todo
	if err := dao.DB.Where("id = ? AND deleted_at IS NULL", id).First(&existingTodo).Error; err != nil {
		return err
	}
	// 创建一个 map 来存储要更新的字段
	dataToUpdate := make(map[string]interface{})
	// 如果Title字段非空, 则需要更新此字段
	if todo.Title != "" {
		dataToUpdate["title"] = todo.Title
	}

	// 使用指针以区分是否提供了状态
	if todo.Status != nil {
		dataToUpdate["status"] = *todo.Status
	}
	// 如果 dataToUpdate 为空，表示没有要更新的字段
	if len(dataToUpdate) == 0 {
		return errors.New("no fields provided for update")
	}
	err = dao.DB.Model(&Todo{}).Where("id = ?", id).Updates(dataToUpdate).Error
	return err
}

func DeleteATodo(id *int) (err error) {
	result := dao.DB.Where("id = ?", id).Delete(&Todo{})
	if result.Error != nil {
		// 在发生错误时返回错误信息
		return result.Error
	}
	// 检查是否有记录被删除
	if result.RowsAffected == 0 {
		// 如果没有记录被删除，返回相应的错误信息
		return errors.New("todo not found")
	}
	// 没有错误，返回 nil
	return nil
}

/*
	User这个Model的增删改查操作都放在这里
*/

// CreateAUser 创建User
func CreateAUser(user *User) (err error) {
	if err := dao.DB.Create(user).Error; err != nil {
		// 检查错误是否是唯一性冲突
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 返回包含更多信息的唯一性冲突错误
			return fmt.Errorf("failed to create user: %w (username already exists)", err)
		}
		// 返回其他类型的错误
		return fmt.Errorf("failed to create user: %w", err)
	}
	// 插入成功，没有错误
	return nil
}

// GetAllUser 查询所有用户
func GetAllUser() (userList []*User, err error) {
	if err = dao.DB.Find(&userList).Error; err != nil {
		return []*User{}, err
	}
	return userList, nil
}

func GetUserUid(uid int) ([]*User, error) {
	var users []*User
	if err := dao.DB.Where("uid=?", uid).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to get todos for uid %d: %v", uid, err)
	}
	return users, nil
}

// GetUserName   根据username查询是否存在
func GetUserName(username string) (*User, error) {
	user := new(User)
	if err := dao.DB.Where("username = ?", username).First(user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 用户不存在的情况，返回 nil 表示用户未找到
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

// UpdateAUser 更新用户信息
func UpdateAUser(uid *int, user *User) (err error) {
	// 查询用户是否已被删除
	var existingUser User
	if err := dao.DB.Where("uid = ? AND deleted_at IS NULL", uid).First(&existingUser).Error; err != nil {
		// 用户不存在或已删除，返回相应的错误
		return err
	}
	//用户存在，进行更新
	err = dao.DB.Model(&User{}).Where("uid = ?", uid).Updates(map[string]interface{}{
		"username": user.Username,
		"password": user.Password,
	}).Error
	if err != nil {
		// 处理更新失败的情况
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			// 唯一性冲突，返回相应的错误
			return errors.New("username already exists")
		}
		// 其他数据库错误，返回相应的错误
		return errors.New("failed to update user")
	}

	return nil
}

// DeleteAUser 删除用户信息
func DeleteAUser(uid int) (err error) {
	//result := dao.DB.Where("uid = ?", uid).Delete(&User{})
	//if result.Error != nil {
	//	// 在发生错误时返回错误信息
	//	return result.Error
	//}
	//// 检查是否有记录被删除
	//if result.RowsAffected == 0 {
	//	// 如果没有记录被删除，返回相应的错误信息
	//	return errors.New("todo not found")
	//}
	//// 没有错误，返回 nil
	//return nil

	//开启事务
	tx := dao.DB.Begin()
	// 在事务中删除与用户相关的todo记录
	if err := tx.Where("uid = ?", uid).Delete(&Todo{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	// 在事务中删除用户
	result := tx.Where("uid = ?", uid).Delete(&User{})
	if result.Error != nil || result.RowsAffected == 0 {
		tx.Rollback()
		if result.Error != nil {
			return result.Error
		} else {
			return errors.New("user not found")
		}
	}
	// 提交事务
	tx.Commit()
	return nil

}
