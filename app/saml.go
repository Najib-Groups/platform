// Copyright (c) 2017 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"io"
	"mime/multipart"
	"net/http"
	"os"

	"github.com/mattermost/platform/einterfaces"
	"github.com/mattermost/platform/model"
	"github.com/mattermost/platform/utils"
)

func GetSamlMetadata() (string, *model.AppError) {
	samlInterface := einterfaces.GetSamlInterface()
	if samlInterface == nil {
		err := model.NewAppError("GetSamlMetadata", "api.admin.saml.not_available.app_error", nil, "", http.StatusNotImplemented)
		return "", err
	}

	if result, err := samlInterface.GetMetadata(); err != nil {
		return "", model.NewAppError("GetSamlMetadata", "api.admin.saml.metadata.app_error", nil, "err="+err.Message, err.StatusCode)
	} else {
		return result, nil
	}
}

func WriteSamlFile(filename string, fileData *multipart.FileHeader) *model.AppError {
	file, err := fileData.Open()
	defer file.Close()
	if err != nil {
		return model.NewLocAppError("AddSamlCertificate", "api.admin.add_certificate.open.app_error", nil, err.Error())
	}

	out, err := os.Create(utils.FindDir("config") + filename)
	if err != nil {
		return model.NewLocAppError("AddSamlCertificate", "api.admin.add_certificate.saving.app_error", nil, err.Error())
	}
	defer out.Close()

	io.Copy(out, file)
	return nil
}

func AddSamlPublicCertificate(fileData *multipart.FileHeader) *model.AppError {
	if err := WriteSamlFile(model.SAML_SETTING_SP_CERTIFICATE, fileData); err != nil {
		return err
	}

	return nil
}

func AddSamlPrivateCertificate(fileData *multipart.FileHeader) *model.AppError {
	if err := WriteSamlFile(model.SAML_SETTING_SP_PRIVATE_KEY, fileData); err != nil {
		return err
	}

	return nil
}

func AddSamlIdpCertificate(fileData *multipart.FileHeader) *model.AppError {
	if err := WriteSamlFile(model.SAML_SETTINGS_IDP_CERTIFICATE, fileData); err != nil {
		return err
	}

	return nil
}

func RemoveSamlFile(filename string) *model.AppError {
	if err := os.Remove(utils.FindConfigFile(filename)); err != nil {
		return model.NewLocAppError("removeCertificate", "api.admin.remove_certificate.delete.app_error",
			map[string]interface{}{"Filename": filename}, err.Error())
	}

	return nil
}

func RemoveSamlPublicCertificate() *model.AppError {
	if err := RemoveSamlFile(model.SAML_SETTING_SP_CERTIFICATE); err != nil {
		return err
	}

	cfg := &model.Config{}
	*cfg = *utils.Cfg

	*cfg.SamlSettings.Encrypt = false

	if err := cfg.IsValid(); err != nil {
		return err
	}

	utils.SaveConfig(utils.CfgFileName, cfg)
	utils.LoadConfig(utils.CfgFileName)

	return nil
}

func RemoveSamlPrivateCertificate() *model.AppError {
	if err := RemoveSamlFile(model.SAML_SETTING_SP_PRIVATE_KEY); err != nil {
		return err
	}

	cfg := &model.Config{}
	*cfg = *utils.Cfg

	*cfg.SamlSettings.Encrypt = false

	if err := cfg.IsValid(); err != nil {
		return err
	}

	utils.SaveConfig(utils.CfgFileName, cfg)
	utils.LoadConfig(utils.CfgFileName)

	return nil
}

func RemoveSamlIdpCertificate() *model.AppError {
	if err := RemoveSamlFile(model.SAML_SETTINGS_IDP_CERTIFICATE); err != nil {
		return err
	}

	cfg := &model.Config{}
	*cfg = *utils.Cfg

	*cfg.SamlSettings.Enable = false

	if err := cfg.IsValid(); err != nil {
		return err
	}

	utils.SaveConfig(utils.CfgFileName, cfg)
	utils.LoadConfig(utils.CfgFileName)

	return nil
}

func GetSamlCertificateStatus() *model.SamlCertificateStatus {
	status := &model.SamlCertificateStatus{}

	status.IdpCertificateFile = utils.FileExistsInConfigFolder(model.SAML_SETTINGS_IDP_CERTIFICATE)
	status.PrivateKeyFile = utils.FileExistsInConfigFolder(model.SAML_SETTING_SP_PRIVATE_KEY)
	status.PublicCertificateFile = utils.FileExistsInConfigFolder(model.SAML_SETTING_SP_CERTIFICATE)

	return status
}
