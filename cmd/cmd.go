package cmd

import (
	"sshmux/common"
	sshmuxhttp "sshmux/http"
	sshmuxssh "sshmux/ssh"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
)

func loadConfig(cCtx *cli.Context) (*common.Config, *common.API, error) {
	configPath := cCtx.String("config")
	config, err := common.LoadConfig(configPath)
	if err != nil {
		return nil, nil, err
	}
	api, err := common.NewAPI(config.DB)
	if err != nil {
		return nil, nil, err
	}
	return config, api, nil
}

func Passwd(cCtx *cli.Context) error {
	_, api, err := loadConfig(cCtx)
	if err != nil {
		return err
	}

	username := cCtx.Args().Get(0)
	if username == "" {
		return cli.Exit("username is required", 1)
	}
	password := cCtx.Args().Get(1)
	if password == "" {
		return cli.Exit("password is required", 1)
	}

	user := api.GetUserByName(username)
	if user == nil {
		return cli.Exit("user not found", 1)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.Password = string(hashedPassword)
	if err := api.UpdateUser(*user); err != nil {
		return err
	}

	return nil
}

func SetAdmin(cCtx *cli.Context) error {
	_, api, err := loadConfig(cCtx)
	if err != nil {
		return err
	}

	username := cCtx.Args().Get(0)
	if username == "" {
		return cli.Exit("username is required", 1)
	}
	isAdmin := cCtx.Args().Get(1)
	if isAdmin == "" {
		return cli.Exit("isAdmin is required", 1)
	}
	if isAdmin != "true" && isAdmin != "false" {
		return cli.Exit("isAdmin must be true or false", 1)
	}

	user := api.GetUserByName(username)
	if user == nil {
		return cli.Exit("user not found", 1)
	}

	user.IsAdmin = isAdmin == "true"

	if err := api.UpdateUser(*user); err != nil {
		return err
	}

	return nil
}

func UserAdd(cCtx *cli.Context) error {
	_, api, err := loadConfig(cCtx)
	if err != nil {
		return err
	}

	username := cCtx.Args().Get(0)
	if username == "" {
		return cli.Exit("username is required", 1)
	}
	password := cCtx.Args().Get(1)
	if password == "" {
		return cli.Exit("password is required", 1)
	}
	isAdmin := cCtx.Args().Get(2)
	if isAdmin == "" {
		return cli.Exit("isAdmin is required", 1)
	}
	if isAdmin != "true" && isAdmin != "false" {
		return cli.Exit("isAdmin must be true or false", 1)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := common.User{
		Username: username,
		Password: string(hashedPassword),
		IsAdmin:  isAdmin == "true",
	}

	if err := api.CreateUser(user); err != nil {
		return err
	}

	return nil
}

func Serve(cCtx *cli.Context) error {
	config, _, err := loadConfig(cCtx)
	if err != nil {
		return err
	}

	sshServer, err := sshmuxssh.NewServer(config)
	if err != nil {
		return err
	}
	httpServer, err := sshmuxhttp.NewServer(config)
	if err != nil {
		return err
	}

	go sshServer.Start()
	httpServer.Start()

	return nil
}
