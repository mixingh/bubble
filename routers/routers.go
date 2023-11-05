// Package routers +build !excludeSwagger
package routers

import (
	"bubble/controller"
	_ "bubble/docs"
	"bubble/setting"
	"github.com/gin-gonic/gin"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
)

func SetupRouter() *gin.Engine {
	if setting.Conf.Release {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()
	gin.SetMode(gin.DebugMode)
	// 告诉gin框架模板文件引用的静态文件去哪里找
	r.Static("/static", "static")
	// 告诉gin框架去哪里找模板文件
	r.LoadHTMLGlob("templates/*")
	r.StaticFile("/favicon.ico", "./templates/favicon.ico")
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	//主页
	r.GET("/", controller.IndexHandler)

	r.POST("/login", controller.LoginHandler)

	r.POST("/signup", controller.SignUp)

	v1Group := r.Group("v1")
	v1Group.Use(controller.AuthenticationMiddleware())
	{

		v1Group.POST("/todo", controller.CreateTodo)

		v1Group.GET("/todo", controller.GetTodoList)

		v1Group.GET("/todo/:uid", controller.GetTodo)

		v1Group.PUT("/todo/:id", controller.UpdateATodo)

		v1Group.DELETE("/todo/:id", controller.DeleteATodo)

		//用户
		//添加用户（注册）见：r.POST("/signup", controller.SignUp)
		//v1Group.POST("/user", controller.CreateUser)

		v1Group.GET("/user", controller.GetUserList)

		v1Group.GET("/user/:uid", controller.GetUser)

		v1Group.PUT("/user/:uid", controller.UpdateAUser)

		v1Group.DELETE("/user/:uid", controller.DeleteAUser)

		v1Group.POST("/signout", controller.SignOut)
	}

	return r
}
