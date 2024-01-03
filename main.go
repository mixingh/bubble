package main

import (
	"bubble/controller"
	"bubble/dao"
	"bubble/models"
	"bubble/routers"
	"bubble/setting"
	"fmt"
	"os"
)

// @title bubble便签
// @version 1.1
// @description
//该项目是gin+vue的前后端分离项目，使用gorm访问MySQL，其中vue前端是使用vue-element框架简单实现的;go后台使用jwt，对API接口进行权限控制。此外，Web页面在token过期后的半个小时内，用户再次操作会自动刷新token
// @termsOfService http://swagger.io/terms/

// @contact.name riverk
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host 127.0.0.1:9000

const defaultConfFile = "./conf/config.ini"

func main() {
	// 加载配置文件
	confFile := defaultConfFile
	if len(os.Args) > 2 {
		fmt.Println("use specified conf file: ", os.Args[1])
		confFile = os.Args[1]
	} else {
		fmt.Println("no configuration file was specified, use ./conf/config.ini")
	}
	if err := setting.Init(confFile); err != nil {
		fmt.Printf("load config from file failed, err:%v\n", err)
		return
	}
	// 创建数据库
	// sql: CREATE DATABASE bubble;
	// 连接数据库
	err := dao.InitMySQL(setting.Conf.MySQLConfig)
	if err != nil {
		fmt.Printf("init mysql failed, err:%v\n", err)
		return
	}
	defer dao.Close() // 程序退出关闭数据库连接
	// 模型绑定
	dao.DB.AutoMigrate(&models.Todo{}, &models.User{}, &models.BlacklistedToken{})
	// 注册路由
	r := routers.SetupRouter()
	// 启动定期清理任务
	go controller.CleanUpExpiredTokens()

	if err := r.Run(fmt.Sprintf(":%d", setting.Conf.Port)); err != nil {
		fmt.Printf("server startup failed, err:%v\n", err)
	}
	//swagger文档接口
	//r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

}
