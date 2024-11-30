package cmd

import (
	"sshmux/common"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
)

func Passwd(cCtx *cli.Context) error {
	configPath := cCtx.String("config")
	config, err := common.LoadConfig(configPath)
	if err != nil {
		return err
	}
	api, err := common.NewAPI(config.DB)
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
	configPath := cCtx.String("config")
	config, err := common.LoadConfig(configPath)
	if err != nil {
		return err
	}
	api, err := common.NewAPI(config.DB)
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
	configPath := cCtx.String("config")
	config, err := common.LoadConfig(configPath)
	if err != nil {
		return err
	}
	api, err := common.NewAPI(config.DB)
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
