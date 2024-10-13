package common

import "testing"

func TestCreateTarget(t *testing.T) {
	api, _ := NewAPI("test.db")
	target := Target{
		Name: "pve",
		Host: "222.195.90.155",
		Port: 22,
		User: "root",
	}
	err := api.CreateTarget(target)
	if err != nil {
		t.Errorf("CreateTarget failed: %v", err)
	}
}

func TestCreatePubkey(t *testing.T) {
	api, _ := NewAPI("test.db")
	pubkey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEouP9wQoLlQHpoJkaaLECOXoOBmJYZfGtFihWpiCmn2 maoyachen@maoyachendeMacBook-Pro.local"
	err := api.CreatePubkey(Pubkey{
		UserId: 1,
		Key:    pubkey,
	})
	if err != nil {
		t.Errorf("CreatePubkey failed: %v", err)
	}
}

func TestGetTargetByName(t *testing.T) {
	api, _ := NewAPI("test.db")
	target := api.GetTargetByName("pve1")
	if target != nil {
		t.Logf("target: %v", target)
	}
	// if target == nil {
	// 	t.Errorf("GetTargetByName failed")
	// }
}
