// Copyright (c) 2016 John E. Vincent
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Copyright (c) 2018 Target Brands, Inc.

package artifactory

import (
	"bytes"
	"gopkg.in/yaml.v2"
	"net/http"
)

// SystemService handles communication with the system related
// methods of the Artifactory API.
//
// Docs: https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-SYSTEM&CONFIGURATION
type SystemService service

// Versions represents the version information about Artifactory.
type Versions struct {
	Version  *string   `json:"version,omitempty"`
	Revision *string   `json:"revision,omitempty"`
	Addons   *[]string `json:"addons,omitempty"`
}

func (v Versions) String() string {
	return Stringify(v)
}

// YamlConfig represents the available elements that can be used to apply system configuration.
// We omit repository and replication-based configuration here as the API endpoints should be used.
//
// Docs: https://www.jfrog.com/confluence/display/RTF/YAML+Configuration+File
type YamlConfig struct {
	UrlBase                   *string                    `yaml:"urlBase,omitempty"`
	FileUploadMaxSizeMb       *int                       `yaml:"fileUploadMaxSizeMb,omitempty"`
	DateFormat                *string                    `yaml:"dateFormat,omitempty"`
	OfflineMode               *bool                      `yaml:"offlineMode,omitempty"`
	FolderDownloadConfig      *FolderDownloadConfig      `yaml:"folderDownloadConfig,omitempty"`
	ReplicationsConfig        *ReplicationsConfig        `yaml:"replicationsConfig,omitempty"`
	SystemMessageConfig       *SystemMessageConfig       `yaml:"systemMessageConfig,omitempty"`
	TrashCanConfig            *TrashCanConfig            `yaml:"trashCanConfig,omitempty"`
	Proxies                   *map[string]Proxy          `yaml:"proxies,omitempty"`
	MailServer                *MailServer                `yaml:"mailServer,omitempty"`
	Security                  *Security                  `yaml:"security,omitempty"`
	Backups                   *map[string]Backup         `yaml:"backups,omitempty"`
	Indexer                   *Indexer                   `yaml:"indexer,omitempty"`
	GcConfig                  *GcConfig                  `yaml:"gcConfig,omitempty"`
	QuotaConfig               *QuotaConfig               `yaml:"quotaConfig,omitempty"`
	CleanupConfig             *CleanupConfig             `yaml:"cleanupConfig,omitempty"`
	VirtualCacheCleanupConfig *VirtualCacheCleanupConfig `yaml:"virtualCacheCleanupConfig,omitempty"`
}

// FolderDownloadConfig represents Folder Download settings
// in Artifactory General Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-General(General,PropertySets,Proxy,Mail)
type FolderDownloadConfig struct {
	Enabled               *bool `yaml:"enabled,omitempty"`
	MaxConcurrentRequests *int  `yaml:"maxConcurrentRequests,omitempty"`
	MaxDownloadSizeMb     *int  `yaml:"maxDownloadSizeMb,omitempty"`
	MaxFiles              *int  `yaml:"maxFiles,omitempty"`
	EnabledForAnonymous   *bool `yaml:"enabledForAnonymous,omitempty"`
}

// ReplicationsConfig represents Global Replication Blocking
// settings in Artifactory General Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-General(General,PropertySets,Proxy,Mail)
type ReplicationsConfig struct {
	BlockPullReplications *bool `yaml:"blockPullReplications,omitempty"`
	BlockPushReplications *bool `yaml:"blockPushReplications,omitempty"`
}

// SystemMessageConfig represents Custom Message settings in Artifactory General Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-General(General,PropertySets,Proxy,Mail)
type SystemMessageConfig struct {
	Enabled        *bool   `yaml:"enabled,omitempty"`
	Message        *string `yaml:"message,omitempty"`
	Title          *string `yaml:"title,omitempty"`
	TitleColor     *string `yaml:"titleColor,omitempty"`
	ShowOnAllPages *bool   `yaml:"showOnAllPages,omitempty"`
}

// TrashCanConfig represents Trash Can settings in Artifactory General Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-General(General,PropertySets,Proxy,Mail)
type TrashCanConfig struct {
	Enabled             *bool `yaml:"enabled,omitempty"`
	RetentionPeriodDays *bool `yaml:"retentionPeriodDays,omitempty"`
}

// PropertySet represents a Property Set in Artifactory General Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-General(General,PropertySets,Proxy,Mail)
type PropertySet struct {
	Properties *[]Property `yaml:"properties,omitempty"`
	Visible    *bool       `yaml:"visible,omitempty"`
}

// Property represents a Property in a Property Set in Artifactory General Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-General(General,PropertySets,Proxy,Mail)
type Property struct {
	Name             *string `yaml:"name,omitempty"`
	PredefinedValues *map[string]struct {
		DefaultValue *bool `yaml:"defaultValue,omitempty"`
	} `yaml:"predefinedValues,omitempty"`
	ClosedPredefinedValues *bool `yaml:"closedPredefinedValues,omitempty"`
	MultipleChoice         *bool `yaml:"multipleChoice,omitempty"`
}

// Proxy represents a Proxy setting in Artifactory General Configuration..
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-General(General,PropertySets,Proxy,Mail)
type Proxy struct {
	Domain          *string `yaml:"domain,omitempty"`
	Host            *string `yaml:"host,omitempty"`
	NtHost          *string `yaml:"ntHost,omitempty"`
	Password        *string `yaml:"password,omitempty"`
	Port            *int    `yaml:"port,omitempty"`
	RedirectToHosts *string `yaml:"redirectToHosts,omitempty"`
	Username        *string `yaml:"username,omitempty"`
	DefaultProxy    *bool   `yaml:"defaultProxy,omitempty"`
}

// MailServer represents a Mail Server setting in Artifactory General Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-General(General,PropertySets,Proxy,Mail)
type MailServer struct {
	Enabled        *bool   `yaml:"enabled,omitempty"`
	ArtifactoryUrl *string `yaml:"artifactoryUrl,omitempty"`
	From           *string `yaml:"from,omitempty"`
	Host           *string `yaml:"host,omitempty"`
	Username       *string `yaml:"username,omitempty"`
	Password       *string `yaml:"password,omitempty"`
	Port           *int    `yaml:"port,omitempty"`
	SubjectPrefix  *string `yaml:"subjectPrefix,omitempty"`
	Ssl            *bool   `yaml:"ssl,omitempty"`
	Tls            *bool   `yaml:"tls,omitempty"`
}

// Security represents the possible Security settings in Artifactory Security Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Security(Generalsecurity,PasswordPolicy,LDAP,SAML,OAuth,HTTPSSO,Crowd)
type Security struct {
	AnonAccessEnabled             *bool `yaml:"anonAccessEnabled,omitempty"`
	AnonAccessToBuildInfoDisabled *bool `yaml:"anonAccessToBuildInfoDisabled,omitempty"`
	UserLockPolicy                *struct {
		Enabled       *bool `yaml:"enabled,omitempty"`
		LoginAttempts *int  `yaml:"loginAttempts,omitempty"`
	} `yaml:"userLockPolicy,omitempty"`
	PasswordSettings  *PasswordSettings            `yaml:"passwordSettings,omitempty"`
	LdapSettings      *map[string]LdapSetting      `yaml:"ldapSettings,omitempty"`
	LdapGroupSettings *map[string]LdapGroupSetting `yaml:"ldapGroupSettings,omitempty"`
	CrowdSettings     *CrowdSettings               `yaml:"crowdSettings,omitempty"`
	SamlSettings      *SamlSettings                `yaml:"samlSettings,omitempty"`
}

// Security represents the Password settings in Artifactory Security Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Security(Generalsecurity,PasswordPolicy,LDAP,SAML,OAuth,HTTPSSO,Crowd)
type PasswordSettings struct {
	EncryptionPolicy *string `yaml:"encryptionPolicy,omitempty"`
	ExpirationPolicy *struct {
		Enabled        *bool `yaml:"enabled,omitempty"`
		PasswordMaxAge *int  `yaml:"passwordMaxAge,omitempty"`
		NotifyByEmail  *bool `yaml:"notifyByEmail,omitempty"`
	} `yaml:"expirationPolicy,omitempty"`
}

// LdapSetting represents the LDAP settings in Artifactory Security Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Security(Generalsecurity,PasswordPolicy,LDAP,SAML,OAuth,HTTPSSO,Crowd)
type LdapSetting struct {
	EmailAttribute          *string `yaml:"emailAttribute,omitempty"`
	LdapPoisoningProtection *bool   `yaml:"ldapPoisoningProtection,omitempty"`
	LdapUrl                 *string `yaml:"ldapUrl,omitempty"`
	Search                  *struct {
		ManagerDn       *string `yaml:"managerDn,omitempty"`
		ManagerPassword *string `yaml:"managerPassword,omitempty"`
		SearchBase      *string `yaml:"searchBase,omitempty"`
		SearchFilter    *string `yaml:"searchFilter,omitempty"`
		SearchSubTree   *bool   `yaml:"searchSubTree,omitempty"`
	} `yaml:"search,omitempty"`
	UserDnPattern            *string `yaml:"userDnPattern,omitempty"`
	AllowUserToAccessProfile *bool   `yaml:"allowUserToAccessProfile,omitempty"`
	AutoCreateUser           *bool   `yaml:"autoCreateUser,omitempty"`
	Enabled                  *bool   `yaml:"enabled,omitempty"`
}

// LdapGroupSetting represents the LDAP Group settings in Artifactory Security Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Security(Generalsecurity,PasswordPolicy,LDAP,SAML,OAuth,HTTPSSO,Crowd)
type LdapGroupSetting struct {
	DescriptionAttribute *string `yaml:"descriptionAttribute,omitempty"`
	EnabledLdap          *string `yaml:"enabledLdap,omitempty"`
	Filter               *string `yaml:"filter,omitempty"`
	GroupBaseDn          *string `yaml:"groupBaseDn,omitempty"`
	GroupMemberAttribute *string `yaml:"groupMemberAttribute,omitempty"`
	GroupNameAttribute   *string `yaml:"groupNameAttribute,omitempty"`
	Strategy             *string `yaml:"strategy,omitempty"`
	SubTree              *bool   `yaml:"subtree,omitempty"`
}

// CrowdSettings represents the Crowd settings in Artifactory Security Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Security(Generalsecurity,PasswordPolicy,LDAP,SAML,OAuth,HTTPSSO,Crowd)
type CrowdSettings struct {
	ApplicationName           *string `yaml:"applicationName,omitempty"`
	Password                  *string `yaml:"password,omitempty"`
	ServerUrl                 *string `yaml:"serverUrl,omitempty"`
	SessionValidationInterval *int    `yaml:"sessionValidationInterval,omitempty"`
	EnableIntegration         *bool   `yaml:"enableIntegration,omitempty"`
	NoAutoUserCreation        *bool   `yaml:"noAutoUserCreation,omitempty"`
	UseDefaultProxy           *bool   `yaml:"useDefaultProxy,omitempty"`
}

// SamlSettings represents the SAML settings in Artifactory Security Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Security(Generalsecurity,PasswordPolicy,LDAP,SAML,OAuth,HTTPSSO,Crowd)
type SamlSettings struct {
	EnableIntegration        *bool   `yaml:"enableIntegration,omitempty"`
	Certificate              *string `yaml:"certificate,omitempty"`
	EmailAttribute           *string `yaml:"emailAttribute,omitempty"`
	GroupAttribute           *string `yaml:"groupAttribute,omitempty"`
	LoginUrl                 *string `yaml:"loginUrl,omitempty"`
	LogoutUrl                *string `yaml:"logoutUrl,omitempty"`
	NoAutoUserCreation       *bool   `yaml:"noAutoUserCreation,omitempty"`
	ServiceProviderName      *string `yaml:"serviceProviderName,omitempty"`
	AllowUserToAccessProfile *bool   `yaml:"allowUserToAccessProfile,omitempty"`
	AutoRedirect             *bool   `yaml:"autoRedirect,omitempty"`
	SyncGroups               *bool   `yaml:"syncGroups,omitempty"`
}

// OauthSettings represents the OAuth settings in Artifactory Security Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Security(Generalsecurity,PasswordPolicy,LDAP,SAML,OAuth,HTTPSSO,Crowd)
type OauthSettings struct {
	AllowUserToAccessProfile *bool                            `yaml:"allowUserToAccessProfile,omitempty"`
	EnableIntegration        *bool                            `yaml:"enableIntegration,omitempty"`
	PersistUsers             *bool                            `yaml:"persistUsers,omitempty"`
	OauthProvidersSettings   *map[string]OauthProviderSetting `yaml:"oauthProvidersSettings,omitempty"`
}

// OauthProviderSetting represents the Oauth Provider settings in Artifactory Security Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Security(Generalsecurity,PasswordPolicy,LDAP,SAML,OAuth,HTTPSSO,Crowd)
type OauthProviderSetting struct {
	ApiUrl       *string `yaml:"apiUrl,omitempty"`
	AuthUrl      *string `yaml:"authUrl,omitempty"`
	BasicUrl     *string `yaml:"basicUrl,omitempty"`
	Enabled      *bool   `yaml:"enabled,omitempty"`
	ProviderType *string `yaml:"providerType,omitempty"`
	Secret       *string `yaml:"secret,omitempty"`
	TokenUrl     *string `yaml:"tokenUrl,omitempty"`
}

// HttpSsoSettings represents the HTTP SSO settings in Artifactory Security Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Security(Generalsecurity,PasswordPolicy,LDAP,SAML,OAuth,HTTPSSO,Crowd)
type HttpSsoSettings struct {
	HttpSsoProxied            *bool   `yaml:"httpSsoProxied,omitempty"`
	RemoteUserRequestVariable *string `yaml:"remoteUserRequestVariable,omitempty"`
	AllowUserToAccessProfile  *bool   `yaml:"allowUserToAccessProfile,omitempty"`
	NoAutoUserCreation        *bool   `yaml:"noAutoUserCreation,omitempty"`
}

// Backup represents the Backup settings in Artifactory Services Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Servicesconfiguration(Backups,MavenIndexer)
type Backup struct {
	CronExp                *string   `yaml:"cronExp,omitempty"`
	ExcludedRepositories   *[]string `yaml:"excludedRepositories,omitempty"`
	RetentionPeriodHours   *int      `yaml:"retentionPeriodHours,omitempty"`
	CreateArchive          *bool     `yaml:"createArchive,omitempty"`
	Enabled                *bool     `yaml:"enabled,omitempty"`
	ExcludeBuilds          *bool     `yaml:"excludeBuilds,omitempty"`
	ExcludeNewRepositories *bool     `yaml:"excludeNewRepositories,omitempty"`
	SendMailOnError        *bool     `yaml:"sendMailOnError,omitempty"`
}

// Indexer represents the Maven Indexer settings in Artifactory Services Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Servicesconfiguration(Backups,MavenIndexer)
type Indexer struct {
	Enabled              *bool     `yaml:"enabled,omitempty"`
	CronExp              *string   `yaml:"cronExp,omitempty"`
	IncludedRepositories *[]string `yaml:"includedRepositories,omitempty"`
}

// GcConfig represents the Garbage Collection settings in Artifactory Maintenance Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Servicesconfiguration(Backups,MavenIndexer)
type GcConfig struct {
	CronExp *string `yaml:"cronExp,omitempty"`
}

// QuotaConfig represents the Storage Quota settings in Artifactory Maintenance Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Servicesconfiguration(Backups,MavenIndexer)
type QuotaConfig struct {
	DiskSpaceLimitPercentage   *int  `yaml:"diskSpaceLimitPercentage,omitempty"`
	DiskSpaceWarningPercentage *int  `yaml:"diskSpaceWarningPercentage,omitempty"`
	Enabled                    *bool `yaml:"enabled,omitempty"`
}

// CleanupConfig represents the Cleanup Unused Cached Artifacts settings in Artifactory Maintenance Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Servicesconfiguration(Backups,MavenIndexer)
type CleanupConfig struct {
	CronExp *string `yaml:"cronExp,omitempty"`
}

// VirtualCacheCleanupConfig represents the Cleanup Virtual Repositories settings in Artifactory Maintenance Configuration.
//
// Docs: https://www.jfrog.com/confluence/display/RTF6X/YAML+Configuration+File#YAMLConfigurationFile-Servicesconfiguration(Backups,MavenIndexer)
type VirtualCacheCleanupConfig struct {
	CronExp *string `yaml:"cronExp,omitempty"`
}

// Ping returns a simple status response.
//
// Docs: https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-SystemHealthPing
func (s *SystemService) Ping() (*string, *Response, error) {
	u := "/api/system/ping"
	v := new(string)

	resp, err := s.client.Call("GET", u, nil, v)
	return v, resp, err
}

// Get returns the general system information.
//
// Docs: https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-SystemInfo
func (s *SystemService) Get() (*string, *Response, error) {
	u := "/api/system"
	v := new(string)

	resp, err := s.client.Call("GET", u, nil, v)
	return v, resp, err
}

// Get returns the general system configuration (artifactory.config.xml).
//
// Docs: https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-GeneralConfiguration
func (s *SystemService) GetConfiguration() (*string, *Response, error) {
	u := "/api/system/configuration"
	v := new(string)

	resp, err := s.client.Call("GET", u, nil, v)
	return v, resp, err
}

// ApplyYAMLConfiguration applies the provided system configuration to Artifactory.
//
// Docs: https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-GeneralConfiguration
func (s *SystemService) ApplyYAMLConfiguration(yamlConfig YamlConfig) (*string, *Response, error) {
	u, err := s.client.buildURLForRequest("/api/system/configuration")
	if err != nil {
		return nil, nil, err
	}

	buf := new(bytes.Buffer)
	err = yaml.NewEncoder(buf).Encode(yamlConfig)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("PATCH", u, buf)
	if err != nil {
		return nil, nil, err
	}

	// Apply authentication
	if s.client.Authentication.HasAuth() {
		s.client.addAuthentication(req)
	}

	req.Header.Add("Content-Type", "application/yaml")

	v := new(string)
	resp, err := s.client.Do(req, v)
	if err != nil {
		return v, resp, err
	}

	return v, resp, err
}

// GetVersionAndAddOns returns information about the current version, revision, and installed add-ons.
//
// Docs: https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-VersionandAdd-onsinformation
func (s *SystemService) GetVersionAndAddOns() (*Versions, *Response, error) {
	u := "/api/system/version"
	v := new(Versions)

	resp, err := s.client.Call("GET", u, nil, v)
	return v, resp, err
}
