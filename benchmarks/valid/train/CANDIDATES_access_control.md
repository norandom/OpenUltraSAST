# Training-set candidates for the maintainer's spot-check

Generated 2026-10-13 by `benchmarks/valid/train/sourcing.py candidates`. Every location below passed all three
model checks (vulnerable before the fix, fix addresses it, reachable from an in-repo entry point) and waits for a
human accept or reject. Nothing here is a positive until accepted. Accept or reject a location with

    .venv/bin/python -m benchmarks.valid.verify spot-check benchmarks/valid/train/verification.json <id> accept|reject --reviewer <you> --date YYYY-MM-DD

Sites passing: 69 in 27 repositories, 27 positive changes (fix commits); languages: java 63, javascript 2, php 2, python 1, typescript 1

The verifier's entry point is the model's claim, not a checked fact; it is the reason the site passed the reachability check.

## apache/seatunnel

- advisory: GHSA-9x53-gr7p-4qf5 (access_control, CWE-306), origin `?`, ecosystem ?, licence ?
- fix `53325aa3e76e3939f41a4bf3eaaf3ee56f13f311`, parent (fix^1) `8a9db476bdc37d5e4079491bdb7092b892a17a7b`
- advisory title: Apache SeaTunnel: Unauthenticated insecure access

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `apache-seatunnel-aff20b2911a11f57` | `seatunnel-engine/seatunnel-engine-server/src/main/java/org/apache/seatunnel/engine/server/JettyService.java::JettyService` (88-100) | java | /hazelcast/rest/maps/submit-job (SubmitJobServlet) via JettyService.createJettyServer | 0.75 |

## friendsofflarum/byobu

- advisory: GHSA-6gjm-6wj6-4px5 (access_control, CWE-863), origin `?`, ecosystem ?, licence ?
- fix `23dcf93a30f948d30c678a96681f7fdefeba5171`, parent (fix^1) `2e99cdb7e356a259ea90aa7f84a71fc0f050e006`
- advisory title: Byobu user preference to prevent private discussions being started are not respected

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `friendsofflarum-byobu-7173b8a509cf3e27` | `js/src/forum/extend/User.js::extend` (19-62) | javascript | UserControls 'userControls' extension rendering the private-discussion button on a user's profile page; source is the target user's blocksPd/cannotBeDirectMessaged attributes | 0.75 |
| `friendsofflarum-byobu-f34c4fa78b9178db` | `js/src/forum/pages/PrivateDiscussionsUserPage.js::actionItems` (55-66) | javascript | PrivateDiscussionsUserPage.actionItems rendered via content() on the user private discussions page route (m.route.param('username')) | 0.75 |

## jenkinsci/analysis-core-plugin

- advisory: GHSA-vvfj-p4jf-j8rm (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `3d7a0c7907d831c58541508b893dcea2039809c5`, parent (fix^1) `892ab94f85a49d8c04b302c9bf48b112efe97536`
- advisory title: Missing permission check in Jenkins Static Analysis Utilities Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-analysis-core-plugin-e02e86e3c18ec1d6` | `src/main/java/hudson/plugins/analysis/graph/DefaultGraphConfigurationView.java::persistValue` (126-136) | java | DefaultGraphConfigurationView#doSave form handler (configureDefaults URL) via StaplerRequest | 0.85 |

## jenkinsci/azure-credentials-plugin

- advisory: GHSA-7j55-28qq-676g (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `64da8176c83a41bb83d3ad759628c9bd275b42f5`, parent (fix^1) `887e0f9e898b2765d78e53c7b39017b8d6295dca`
- advisory title: Missing Authorization in Jenkins Azure Credentials Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-azure-credentials-plugin-0dab78b4ed2c29bb` | `src/main/java/com/microsoft/jenkins/keyvault/SecretStringCredentials.java::doVerifyConfiguration` (46-64) | java | Jenkins Stapler HTTP endpoint /descriptorByName/com.microsoft.jenkins.keyvault.SecretStringCredentials/doVerifyConfiguration (doVerifyConfiguration in DescriptorImpl), invoked via web request with ser | 0.85 |
| `jenkinsci-azure-credentials-plugin-144d42edd4fea476` | `src/main/java/com/microsoft/jenkins/keyvault/BaseSecretCredentials.java::doFillServicePrincipalIdItems` (97-103) | java | Jenkins Stapler web endpoint doFillServicePrincipalIdItems on the Azure Credentials DescriptorImpl (form fill for servicePrincipalId), reachable by any user with Overall/Read permission | 0.85 |
| `jenkinsci-azure-credentials-plugin-81c51344b9d31af8` | `src/main/java/com/microsoft/azure/util/AzureCredentials.java::doVerifyConfiguration` (772-800) | java | Jenkins Stapler HTTP endpoint doVerifyConfiguration on AzureCredentials.DescriptorImpl, invoked via form validation request with query parameters (subscriptionId, clientId, clientSecret, etc.) | 0.85 |
| `jenkinsci-azure-credentials-plugin-a83f939fb055e6a0` | `src/main/java/com/microsoft/azure/util/AzureCredentials.java::doFillCertificateIdItems` (802-808) | java | Jenkins Stapler web method doFillCertificateIdItems on AzureCredentials.DescriptorImpl, invoked via the credentials configuration form (e.g. /descriptorByName/com.microsoft.azure.util.AzureCredentials | 0.85 |
| `jenkinsci-azure-credentials-plugin-af7645f7ae48e24c` | `src/main/java/com/microsoft/jenkins/keyvault/SecretCertificateCredentials.java::doVerifyConfiguration` (105-134) | java | Jenkins Stapler HTTP endpoint DescriptorImpl.doVerifyConfiguration (form validation endpoint) invoked via web request with @QueryParameter servicePrincipalId/secretIdentifier/password | 0.85 |
| `jenkinsci-azure-credentials-plugin-bd1228731e6d22aa` | `src/main/java/com/microsoft/azure/util/AzureImdsCredentials.java::validate` (55-94) | java | DescriptorImpl.doVerifyConfiguration (@POST, @QueryParameter subscriptionId/clientId/azureEnvironmentName) | 0.75 |
| `jenkinsci-azure-credentials-plugin-d3c1129ce0199756` | `src/main/java/com/microsoft/azure/util/AzureImdsCredentials.java::doVerifyConfiguration` (107-128) | java | Jenkins DescriptorImpl.doVerifyConfiguration (AzureImdsCredentials) exposed via Stapler HTTP endpoint /descriptorByName/.../doVerifyConfiguration with @QueryParameter subscriptionId, clientId, azureEn | 0.85 |

## jenkinsci/azure-keyvault-plugin

- advisory: GHSA-gf8w-6hcm-rh3j (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `f09ed652cc572d8ba5d7c8c8f9972fd241883c21`, parent (fix^1) `36680c54a27685d6d35d75135daa6e386a107a1b`
- advisory title: Missing permission checks in Jenkins Azure Key Vault Plugin allow enumerating credentials IDs

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-azure-keyvault-plugin-a9975f6d8b4f1568` | `src/main/java/org/jenkinsci/plugins/azurekeyvaultplugin/AzureKeyVaultBuildWrapper.java::SuppressWarnings` (290-295) | java | Jenkins Stapler HTTP endpoint doFillCredentialIDOverrideItems on AzureKeyVaultBuildWrapper.DescriptorImpl (form fill for credentialIDOverride field), reachable by any user with Overall/Read permission | 0.85 |
| `jenkinsci-azure-keyvault-plugin-abd182ce20617255` | `src/main/java/org/jenkinsci/plugins/azurekeyvaultplugin/AzureKeyVaultStep.java::SuppressWarnings` (218-223) | java | DescriptorImpl.doFillCredentialIDItems (Jenkins Stapler HTTP endpoint /job/.../descriptorByName/.../fillCredentialIDItems) | 0.75 |

## jenkinsci/blueocean-plugin

- advisory: GHSA-vc7g-4269-f7hw (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `659a66aff0d0ad693eab9d2807985d591e102aab`, parent (fix^1) `966da5a824c0e78767ba8b6a40be2ebfd8d8919f`
- advisory title: Missing permission check in Blue Ocean Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-blueocean-plugin-5aa4f2eb0a53ebfe` | `blueocean-github-pipeline/src/main/java/io/jenkins/blueocean/blueocean_github_pipeline/GithubServerContainer.java::create` (56-145) | java | GithubServerContainer.create(@JsonBody JSONObject request) invoked via Blue Ocean HTTP endpoint for creating GitHub server; attacker-controlled source is the 'apiUrl' field in the JSON request body, w | 0.85 |
| `jenkinsci-blueocean-plugin-e4ad2dadd845ec00` | `blueocean-bitbucket-pipeline/src/main/java/io/jenkins/blueocean/blueocean_bitbucket_pipeline/server/BitbucketServerEndpointContainer.java::create` (44-97) | java | Blue Ocean REST endpoint POST /blueocean/rest/.../servers (ScmServerEndpointContainer.create) accepting JSONObject request with attacker-controlled API_URL | 0.75 |

## jenkinsci/compuware-scm-downloader-plugin

- advisory: GHSA-75fc-fv3p-xh82 (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `bf00665b13641351a9f67027bbe34609cc4f65e2`, parent (fix^1) `115f057078baad506e2b34b74f4f0600f81990b3`
- advisory title: Jenkins Compuware Source Code Download is missing authorization

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-compuware-scm-downloader-plugin-29636a1534a39217` | `src/main/java/com/compuware/jenkins/scm/PdsConfiguration.java::doFillConnectionIdItems` (254-276) | java | Jenkins Stapler HTTP endpoint doFillConnectionIdItems (e.g. /job/<name>/descriptorByName/.../fillConnectionIdItems) invoked via config.jelly connectionId field; attacker-controlled source is the HTTP  | 0.85 |
| `jenkinsci-compuware-scm-downloader-plugin-316557e9fdf67223` | `src/main/java/com/compuware/jenkins/scm/IspwContainerConfiguration.java::doFillConnectionIdItems` (312-334) | java | Jenkins Stapler HTTP endpoint doFillConnectionIdItems (e.g. /job/<name>/descriptorByName/.../fillConnectionIdItems) invoked via config.jelly connectionId field; attacker-controlled source is the HTTP  | 0.85 |
| `jenkinsci-compuware-scm-downloader-plugin-4b64810cb01a07f5` | `src/main/java/com/compuware/jenkins/scm/AbstractConfiguration.java::doFillCredentialsIdItems` (107-131) | java | Jenkins Stapler HTTP endpoint doFillCredentialsIdItems (e.g. /job/<name>/descriptorByName/.../fillCredentialsIdItems) invoked with Overall/Read permission; attacker-controlled source is the credential | 0.85 |
| `jenkinsci-compuware-scm-downloader-plugin-936a096a4a941ee5` | `src/main/java/com/compuware/jenkins/scm/EndevorConfiguration.java::doFillConnectionIdItems` (255-277) | java | Jenkins Stapler HTTP endpoint doFillConnectionIdItems (e.g. /job/<name>/descriptorByName/.../fillConnectionIdItems) invoked via config.jelly connectionId field; attacker-controlled source is the HTTP  | 0.85 |
| `jenkinsci-compuware-scm-downloader-plugin-c416a32628e63296` | `src/main/java/com/compuware/jenkins/scm/IspwConfiguration.java::doFillConnectionIdItems` (416-438) | java | Jenkins Stapler HTTP endpoint doFillConnectionIdItems (e.g. /job/<name>/descriptorByName/.../fillConnectionIdItems) invoked via @QueryParameter connectionId | 0.85 |

## jenkinsci/compuware-topaz-for-total-test-plugin

- advisory: GHSA-x5gv-5rqv-654m (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `0ba4274d545eac39e3db48b5dfb4512db3242946`, parent (fix^1) `5fca6eb21599f8f27323dfa17a6e44f8176ca551`
- advisory title: Jenkins Compuware Topaz for Total Test Plugin allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-compuware-topaz-for-total-test-plugin-0fcc9e440100be20` | `src/main/java/com/compuware/jenkins/totaltest/TotalTestBuilder.java::doFillCredentialsIdItems` (857-889) | java | Jenkins Stapler HTTP endpoint doFillCredentialsIdItems (descriptor form fill for credentialsId), reachable via Overall/Read authenticated user; source is the credentialsId query parameter and the cred | 0.85 |
| `jenkinsci-compuware-topaz-for-total-test-plugin-31007615cf224711` | `src/main/java/com/compuware/jenkins/totaltest/TotalTestCTBuilder.java::doFillConnectionIdItems` (1534-1556) | java | Jenkins Stapler HTTP endpoint doFillConnectionIdItems (e.g. /job/<name>/descriptorByName/.../fillConnectionIdItems) invoked with Overall/Read permission; @QueryParameter connectionId is attacker-contr | 0.85 |
| `jenkinsci-compuware-topaz-for-total-test-plugin-3b2dc3167c986714` | `src/main/java/com/compuware/jenkins/totaltest/TotalTestBuilder.java::doFillConnectionIdItems` (798-820) | java | Jenkins Stapler HTTP endpoint doFillConnectionIdItems (e.g. /job/<name>/descriptorByName/.../fillConnectionIdItems) invoked via @QueryParameter connectionId | 0.85 |
| `jenkinsci-compuware-topaz-for-total-test-plugin-8659f27b971d364f` | `src/main/java/com/compuware/jenkins/totaltest/TotalTestCTBuilder.java::doFillCredentialsIdItems` (1644-1670) | java | Jenkins Stapler HTTP endpoint doFillCredentialsIdItems on TotalTestCTBuilder (e.g. /job/<name>/descriptorByName/.../fillCredentialsIdItems), invoked via @QueryParameter credentialsId with Overall/Read | 0.85 |
| `jenkinsci-compuware-topaz-for-total-test-plugin-b0ca3df515237e75` | `src/main/java/com/compuware/jenkins/totaltest/TotalTestCTBuilder.java::doFillServerUrlItems` (1681-1773) | java | Jenkins Stapler HTTP endpoint doFillServerUrlItems / doFillServerCredentialsIdItems (form fill methods invoked via Jenkins UI/HTTP request with Overall/Read permission) | 0.85 |
| `jenkinsci-compuware-topaz-for-total-test-plugin-e724ca5f96b58ee5` | `src/main/java/com/compuware/jenkins/totaltest/TotalTestCTBuilder.java::doFillServerCredentialsIdItems` (1740-1766) | java | Jenkins Stapler HTTP endpoint doFillServerCredentialsIdItems (descriptor form fill method) reachable via the build step configuration UI; attacker-controlled source is the @QueryParameter serverCreden | 0.85 |

## jenkinsci/conjur-credentials-plugin

- advisory: GHSA-372f-jc47-7gr5 (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `eda06cde26cdf2d40ae4e2f4d2709e8174489068`, parent (fix^1) `811b0672d5a88d2145823f7355619ddd5f328e17`
- advisory title: Missing permission check in Jenkins Conjur Secrets Plugin allows enumerating credentials IDs

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-conjur-credentials-plugin-11205c0022207637` | `src/main/java/org/conjur/jenkins/conjursecrets/ConjurSecretCredentialsDescriptor.java::doFillCredentialIDItems` (22-27) | java | Jenkins Stapler HTTP endpoint doFillCredentialIDItems (form fill for credential ID field), invoked via web request with uri query parameter | 0.75 |
| `jenkinsci-conjur-credentials-plugin-25bfc860016819fb` | `src/main/java/org/conjur/jenkins/conjursecrets/ConjurSecretUsernameSSHKeyCredentialsImpl.java::doFillCredentialIDItems` (98-104) | java | Jenkins Stapler HTTP endpoint doFillCredentialIDItems on ConjurSecretUsernameSSHKeyCredentialsImpl.DescriptorImpl, invoked via the credentials form fill (e.g. credentialID field) with @QueryParameter  | 0.85 |
| `jenkinsci-conjur-credentials-plugin-f42fa606284883ea` | `src/main/java/org/conjur/jenkins/conjursecrets/ConjurSecretUsernameCredentialsImpl.java::doFillCredentialIDItems` (96-103) | java | Jenkins Stapler HTTP endpoint doFillCredentialIDItems on ConjurSecretUsernameCredentialsImpl.DescriptorImpl, invoked via the credentials form fill (e.g. /descriptorByName/.../fillCredentialIDItems) wi | 0.85 |

## jenkinsci/crx-content-package-deployer-plugin

- advisory: GHSA-4cmq-88f8-53r5 (access_control, CWE-285), origin `?`, ecosystem ?, licence ?
- fix `06cd0e7e1b3f2fb87b3fa332ee1da710ca94b8e1`, parent (fix^1) `1313c422170a064dab0f9359324ff27e30a9f4a5`
- advisory title: Jenkins CRX Content Package Deployer Plugin subject to credentials enumeration via Missing Authorization

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-crx-content-package-deployer-plugin-79286d969348bd3c` | `src/main/java/org/jenkinsci/plugins/graniteclient/GraniteAHCFactory.java::doFillCredentialsIdItems` (149-153) | java | Jenkins Stapler HTTP endpoint /descriptor/.../fillCredentialsIdItems (doFillCredentialsIdItems) invoked via form binding with @QueryParameter value | 0.85 |

## jenkinsci/database-plugin

- advisory: GHSA-hj36-v72x-cc6j (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `7a438d96897af0034cb2e06db0819ca4595c24cb`, parent (fix^1) `a68258cf17ba8d5264010cc760770a62a3cc6c2d`
- advisory title: Missing permission checks in Jenkins Database Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-database-plugin-6a8e141d0c9eaab2` | `src/main/java/org/jenkinsci/plugins/database/AbstractRemoteDatabaseDescriptor.java::doValidate` (24-42) | java | Stapler form validation endpoint doValidate on AbstractRemoteDatabaseDescriptor (e.g. /descriptorByName/.../validate) invoked via HTTP with @QueryParameter hostname, database, username, password, prop | 0.85 |
| `jenkinsci-database-plugin-d2e038dce743f4f4` | `src/main/java/org/jenkinsci/plugins/database/GenericDatabase.java::doCheckDriver` (85-110) | java | Jenkins form validation endpoint /descriptorByName/org.jenkinsci.plugins.database.GenericDatabase/doValidate (and doCheckDriver), invoked via HTTP with attacker-controlled driver, url, username, passw | 0.85 |
| `jenkinsci-database-plugin-fdb5a7fd01260ec1` | `src/main/java/org/jenkinsci/plugins/database/GenericDatabase.java::doValidate` (97-108) | java | Jenkins form validation endpoint doValidate (Descriptor.doValidate) invoked via HTTP POST with query parameters driver, url, username, password | 0.85 |

## jenkinsci/deployer-framework-plugin

- advisory: GHSA-rqqx-fvqx-539g (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `7ba4a55bf3ec567ee5325ea7b24b4086ac1cb3ad`, parent (fix^1) `1d1888e8c0214fa42ee932b3eb26c06a6c7279f0`
- advisory title: Jenkins Deployer Framework Plugin allows attackers with Item/Read permission to read deployment logs

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-deployer-framework-plugin-2929f3e176f304ad` | `src/main/java/com/cloudbees/plugins/deployer/sources/FixedDirectoryDeploySource.java::SuppressWarnings` (195-222) | java | Stapler HTTP endpoint doCheckDirectoryPath (FormValidation) on FixedDirectoryDeploySource.DescriptorImpl, invoked via @QueryParameter fromWorkspace/targetDescriptorId/value | 0.6 |
| `jenkinsci-deployer-framework-plugin-dd5ef66a767e04d5` | `src/main/java/com/cloudbees/plugins/deployer/DeployNowRunAction.java::doDeployText` (361-384) | java | Stapler HTTP endpoint doDeployText (DeployNowRunAction) reachable via URL /job/<job>/<build>/deploy-text or similar Stapler route; attacker-controlled source is the HTTP request handled by StaplerRequ | 0.85 |

## jenkinsci/ec2-plugin

- advisory: GHSA-6hmm-77r2-h6hr (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `0cdbaf2d7da5c368209f427559c8608dec22a63b`, parent (fix^1) `2af0a6da84ef203c463981afbd81da0c0b1b5364`
- advisory title: Missing permission checks in Jenkins Amazon EC2 Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-ec2-plugin-6058527110940076` | `src/main/java/hudson/plugins/ec2/EC2Cloud.java::doTestConnection` (934-959) | java | Jenkins Stapler form validation endpoint doTestConnection on EC2Cloud.DescriptorImpl, invoked via HTTP form validation request with attacker-controlled ec2endpoint, credentialsId, roleArn, roleSession | 0.85 |
| `jenkinsci-ec2-plugin-92278d8bf0b7f60a` | `src/main/java/hudson/plugins/ec2/EC2Cloud.java::doGenerateKey` (960-991) | java | Jenkins Stapler form validation endpoint /descriptorByName/hudson.plugins.ec2.EC2Cloud/doGenerateKey (and doTestConnection), invoked via HTTP with attacker-controlled ec2EndpointUrl, credentialsId, re | 0.85 |

## jenkinsci/electricflow-plugin

- advisory: GHSA-7rx6-4vwv-432g (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `597cbb1d767ae92c44b4cbd9525fa53ddab37117`, parent (fix^1) `fe6308b281ded7377c927b78fb0390d5816ba492`
- advisory title: Missing permission check in Jenkins CloudBees CD Plugin allows scheduling builds

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-electricflow-plugin-b319df3a71ebd890` | `src/main/java/org/jenkinsci/plugins/electricflow/rest/ElectricFlowEFRunAPIAction.java::doBuild` (71-189) | java | HTTP POST to the ElectricFlowEFRunAPIAction endpoint (getUrlName() URL_NAME) invoking doBuild(StaplerRequest, StaplerResponse); attacker-controlled JSON body read via req.getReader() supplies flowRunt | 0.9 |

## jenkinsci/git-plugin

- advisory: GHSA-449w-c77c-vmf6 (access_control, CWE-306), origin `?`, ecosystem ?, licence ?
- fix `b46165c74a0bf15e08763de2e506005624d5d238`, parent (fix^1) `18577d14afa2d1fbf970c44f60fce426d083073b`
- advisory title: Lack of authentication mechanism in Jenkins Git Plugin webhook

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-git-plugin-751c41fb6795520f` | `src/main/java/hudson/plugins/git/GitStatus.java::doNotifyCommit` (115-177) | java | /git/notifyCommit webhook endpoint handled by GitStatus.doNotifyCommit(HttpServletRequest, url, branches, sha1) | 0.95 |

## jenkinsci/global-build-stats-plugin

- advisory: GHSA-gm8g-fh49-qq6v (access_control, CWE-284), origin `?`, ecosystem ?, licence ?
- fix `32aeb0493c4ff5423448576f477ac612f7a25138`, parent (fix^1) `6478447abafa3d984bdfb4f73a358b68a97bdcf3`
- advisory title: Jenkins global-build-stats Plugin missing permission check can result in graph IDs being enumerated

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-global-build-stats-plugin-b2560994597ff44f` | `src/main/java/hudson/plugins/global_build_stats/GlobalBuildStatsPlugin.java::doPython` (130-136) | java | GlobalBuildStatsApi.doPython (and doJson/doXml) REST API endpoint via Stapler, source: buildStatConfigId request parameter | 0.9 |
| `jenkinsci-global-build-stats-plugin-ee8d1b0fdf63b4ee` | `src/main/java/hudson/plugins/global_build_stats/GlobalBuildStatsPlugin.java::doJson` (123-129) | java | GlobalBuildStatsApi.doJson (REST API endpoint /api/json via getApi()), source: buildStatConfigId request parameter | 0.85 |

## jenkinsci/groovy-plugin

- advisory: GHSA-xfwj-2f34-32f5 (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `212e048a319ae32dad4cfec5e73a885a9f4781f0`, parent (fix^1) `da0739d3507c5973d506d18efbda33ad5e37893b`
- advisory title: Jenkins Groovy Plugin sandbox bypass vulnerability

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-groovy-plugin-74141466f39e1a12` | `src/main/java/hudson/plugins/groovy/StringScriptSource.java::doCheckScript` (65-77) | java | Jenkins HTTP endpoint invoking DescriptorImpl.doCheckScript with @QueryParameter String command (Groovy command script source descriptor) | 0.85 |

## jenkinsci/hashicorp-vault-plugin

- advisory: GHSA-vpf7-q2rx-26mh (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `3b38d767aba8bd98d6f4fb53c1f1678d95b5e752`, parent (fix^1) `db858fd6bf48b0784598b8f1b12d006c8d6dec98`
- advisory title: Jenkins HashiCorp Vault Plugin does not perform permission checks in several HTTP endpoints that perform Vault connection tests

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-hashicorp-vault-plugin-4b8dac7099e598b2` | `src/main/java/com/datapipe/jenkins/vault/credentials/common/VaultUsernamePasswordCredentialImpl.java::doTestConnection` (81-105) | java | Jenkins Stapler HTTP endpoint DescriptorImpl.doTestConnection (Vault Username-Password Credential descriptor), invoked via form validation request with attacker-controlled query parameters path, usern | 0.9 |
| `jenkinsci-hashicorp-vault-plugin-69b136827df9a5c0` | `src/main/java/com/datapipe/jenkins/vault/credentials/common/VaultSSHUserPrivateKeyImpl.java::doTestConnection` (115-147) | java | Jenkins Stapler HTTP endpoint doTestConnection on VaultSSHUserPrivateKeyImpl.DescriptorImpl (e.g. /descriptorByName/.../testConnection), with attacker-controlled query parameters path, usernameKey, pr | 0.9 |
| `jenkinsci-hashicorp-vault-plugin-7782cfb6ae3f0339` | `src/main/java/com/datapipe/jenkins/vault/credentials/common/VaultStringCredentialImpl.java::doTestConnection` (59-75) | java | Jenkins Stapler HTTP endpoint doTestConnection on VaultStringCredentialImpl.DescriptorImpl, invoked via the credential configuration form with attacker-controlled query parameters path, vaultKey, pref | 0.85 |
| `jenkinsci-hashicorp-vault-plugin-9f7965aeec3cc869` | `src/main/java/com/datapipe/jenkins/vault/credentials/common/VaultCertificateCredentialsImpl.java::doTestConnection` (139-162) | java | Jenkins Stapler HTTP endpoint DescriptorImpl.doTestConnection (e.g. /descriptorByName/.../testConnection) with @QueryParameter path/keyStoreKey/passwordKey/prefixPath/namespace/engineVersion | 0.85 |
| `jenkinsci-hashicorp-vault-plugin-c76a541ee22b2ef9` | `src/main/java/com/datapipe/jenkins/vault/credentials/common/VaultFileCredentialImpl.java::doTestConnection` (91-120) | java | Jenkins Stapler HTTP endpoint doTestConnection on VaultFileCredentialImpl.DescriptorImpl (e.g. /descriptorByName/com.datapipe.jenkins.vault.credentials.common.VaultFileCredentialImpl/testConnection),  | 0.85 |
| `jenkinsci-hashicorp-vault-plugin-e7d568b004427b1d` | `src/main/java/com/datapipe/jenkins/vault/credentials/common/VaultGCRLoginImpl.java::doTestConnection` (60-78) | java | Jenkins Stapler HTTP endpoint DescriptorImpl.doTestConnection (e.g. /descriptorByName/.../testConnection) with @QueryParameter path/prefixPath/namespace/engineVersion | 0.85 |

## jenkinsci/jiratestresultreporter-plugin

- advisory: GHSA-gc7m-x2cj-3775 (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `0cc6208295b5cb683528e8bf04d139f0bee8eb53`, parent (fix^1) `81792855394237a2f78b06f509985a894ac5c008`
- advisory title: Missing permission check in Jenkins JiraTestResultReporter Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-jiratestresultreporter-plugin-28213733c6b799eb` | `src/main/java/org/jenkinsci/plugins/JiraTestResultReporter/JiraTestDataPublisher.java::doValidateGlobal` (511-544) | java | Jenkins Stapler HTTP endpoint doValidateGlobal on JiraTestDataPublisher (global.jelly 'Validate Settings' button), parameters jiraUrl/username/password | 0.9 |

## jenkinsci/jx-resources-plugin

- advisory: GHSA-xqqr-mq8x-22qx (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `f0d9fb76230b65e851095da936a439d953c5f64d`, parent (fix^1) `520f0a91dd01f404d29cee07433635e43c474294`
- advisory title: Jenkins JX Resources Plugin missing permission check

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-jx-resources-plugin-e1eb49dbe32bfc7a` | `src/main/java/org/jenkinsci/plugins/jx/resources/GlobalPluginConfiguration.java::doValidateClient` (129-141) | java | Jenkins form validation endpoint doValidateClient (GlobalPluginConfiguration), invoked via Jenkins form validation HTTP request with attacker-controlled 'server' and 'namespace' query parameters | 0.85 |

## jenkinsci/mabl-integration-plugin

- advisory: GHSA-m9jj-p947-m8xv (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `4e21f498b0704d62f5a6114fcd8c274a5f440b18`, parent (fix^1) `61281f28815b3e05ca3d156f5b080fdde34ba1df`
- advisory title: Jenkins mabl Plugin missing permission check

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-mabl-integration-plugin-010c7741299085f7` | `src/main/java/com/mabl/integration/jenkins/MablStepBuilder.java::doFillApplicationIdItems` (361-382) | java | Jenkins Stapler HTTP endpoint doFillApplicationIdItems (e.g. /job/<name>/descriptorByName/com.mabl.integration.jenkins.MablStepBuilder/fillApplicationIdItems) with attacker-controlled query parameters | 0.85 |
| `jenkinsci-mabl-integration-plugin-33601449707f721c` | `src/main/java/com/mabl/integration/jenkins/MablStepBuilder.java::doFillRestApiKeyIdItems` (328-342) | java | Jenkins Stapler HTTP endpoint doFillRestApiKeyIdItems (e.g. /job/<name>/descriptorByName/com.mabl.integration.jenkins.MablStepBuilder/fillRestApiKeyIdItems) invoked with attacker-controlled restApiKey | 0.85 |
| `jenkinsci-mabl-integration-plugin-5f366608a3d422b4` | `src/main/java/com/mabl/integration/jenkins/MablStepBuilder.java::getApplicationIdItems` (384-407) | java | doFillApplicationIdItems HTTP endpoint (Jenkins Stapler @QueryParameter restApiKeyId, disableSslVerification, apiBaseUrl, appBaseUrl) reachable by users with Overall/Read permission | 0.85 |
| `jenkinsci-mabl-integration-plugin-60b82fbf81b044f5` | `src/main/java/com/mabl/integration/jenkins/MablStepBuilder.java::doCheckRestApiKeyIds` (344-359) | java | Jenkins Stapler HTTP endpoint doCheckRestApiKeyIds (and doFillApplicationIdItems) on MablStepBuilder, invoked via the mabl build step configuration form; attacker-controlled source is the @QueryParame | 0.85 |
| `jenkinsci-mabl-integration-plugin-8cc76fc9d5aa0984` | `src/main/java/com/mabl/integration/jenkins/MablStepBuilder.java::doFillEnvironmentIdItems` (409-426) | java | Jenkins Stapler HTTP endpoint doFillEnvironmentIdItems (MablStepBuilder), reachable via GET/POST to the descriptor fill URL with attacker-controlled query parameters restApiKeyId, disableSslVerificati | 0.85 |
| `jenkinsci-mabl-integration-plugin-b2206be4bf8e37fb` | `src/main/java/com/mabl/integration/jenkins/MablStepBuilder.java::doValidateForm` (316-326) | java | MablStepDescriptor.doValidateForm HTTP endpoint (Stapler @QueryParameter restApiKeyId/environmentId/applicationId/disableSslVerification/apiBaseUrl/appBaseUrl) | 0.85 |
| `jenkinsci-mabl-integration-plugin-c9df9fe333e3ed08` | `src/main/java/com/mabl/integration/jenkins/MablStepBuilder.java::getEnvironmentIdItems` (428-466) | java | doFillEnvironmentIdItems (Jenkins Stapler HTTP endpoint, @QueryParameter restApiKeyId/apiBaseUrl/appBaseUrl/disableSslVerification) | 0.85 |

## jenkinsci/nomad-plugin

- advisory: GHSA-p278-2qh9-6mwj (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `93ea215a649575e4063e1dfe8361b684c29a91e3`, parent (fix^1) `fe2cc9498561b357c7b1a17fc3b76a492abff755`
- advisory title: Jenkins Nomad Plugin missing permission check

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-nomad-plugin-81a6fad8feb01b11` | `src/main/java/org/jenkinsci/plugins/nomad/NomadCloud.java::doCheckName` (224-233) | java | NomadCloud.DescriptorImpl#doCheckName form validation endpoint (Jenkins Stapler HTTP route /descriptorByName/org.jenkinsci.plugins.nomad.NomadCloud/checkName), source: @QueryParameter String name | 0.75 |

## jenkinsci/opentelemetry-plugin

- advisory: GHSA-f696-867g-2759 (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `f5a4ec123769096ad9a4930ede56588b0fee40f3`, parent (fix^1) `26675a20647122918cb1cf154470e7e71ff1882f`
- advisory title: Jenkins OpenTelemetry Plugin missing permission check allows capturing credentials

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-opentelemetry-plugin-62ce6dc3488e0d80` | `src/main/java/io/jenkins/plugins/opentelemetry/backend/elastic/ElasticLogsBackendWithJenkinsVisualization.java::doCheckElasticsearchCredentialsId` (157-173) | java | Jenkins Stapler HTTP endpoint doCheckElasticsearchCredentialsId (form validation for ElasticLogsBackendWithJenkinsVisualization), invoked via POST with elasticsearchCredentialsId query parameter by a  | 0.85 |
| `jenkinsci-opentelemetry-plugin-c258c6ed37f2c061` | `src/main/java/io/jenkins/plugins/opentelemetry/backend/elastic/ElasticLogsBackendWithJenkinsVisualization.java::doFillElasticsearchCredentialsIdItems` (144-154) | java | Jenkins Stapler HTTP endpoint doFillElasticsearchCredentialsIdItems on the ElasticLogsBackendWithJenkinsVisualization.DescriptorImpl (invoked via the plugin configuration form, e.g. /descriptorByName/ | 0.75 |
| `jenkinsci-opentelemetry-plugin-e7dc96d707803ae7` | `src/main/java/io/jenkins/plugins/opentelemetry/backend/elastic/ElasticLogsBackendWithJenkinsVisualization.java::doCheckElasticsearchUrl` (131-197) | java | Jenkins Stapler HTTP endpoint DescriptorImpl.doValidate (and doCheckElasticsearchUrl/doCheckElasticsearchCredentialsId) invoked via form validation request with attacker-controlled elasticsearchUrl an | 0.85 |
| `jenkinsci-opentelemetry-plugin-f0ff00bf7375eb29` | `src/main/java/io/jenkins/plugins/opentelemetry/backend/elastic/ElasticLogsBackendWithJenkinsVisualization.java::doValidate` (176-195) | java | Jenkins Stapler HTTP endpoint doValidate on ElasticLogsBackendWithJenkinsVisualization (POST form validation), attacker-controlled elasticsearchUrl and elasticsearchCredentialsId query parameters | 0.85 |

## jenkinsci/rocketchatnotifier-plugin

- advisory: GHSA-4p8f-2fwv-6xcw (access_control, CWE-862), origin `?`, ecosystem ?, licence ?
- fix `1a0023be9f2e143434d028d5292ef9dc3195d051`, parent (fix^1) `14cdaa96d98d6d65fbefde1103a04bc478edf415`
- advisory title: Missing permission check in Jenkins RocketChat Notifier Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-rocketchatnotifier-plugin-16d28ce862d5a528` | `src/main/java/jenkins/plugins/rocketchatnotifier/RocketChatNotifier.java::doTestConnection` (581-647) | java | Jenkins Stapler form validation endpoint doTestConnection (e.g. /descriptorByName/jenkins.plugins.rocketchatnotifier.RocketChatNotifier/doTestConnection) with attacker-controlled query parameters rock | 0.9 |

## jenkinsci/support-core-plugin

- advisory: GHSA-w2j3-pq63-339w (access_control, CWE-863), origin `?`, ecosystem ?, licence ?
- fix `9b7a1d48db0fdfb840ca3393e9462e687e69385b`, parent (fix^1) `abaff0102139d9ec56ce3905f2ffef27649c88a4`
- advisory title: Incorrect permission checks in Jenkins Support Core Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-support-core-plugin-3de9ccb2591c7490` | `src/main/java/com/cloudbees/jenkins/support/SupportCommand.java::run` (77-122) | java | Jenkins CLI command 'support' (SupportCommand.run) invoked via CLI channel; attacker-controlled source is the CLI invocation by a user holding Support/DownloadBundle permission | 0.85 |
| `jenkinsci-support-core-plugin-934a17bf668da541` | `src/main/java/com/cloudbees/jenkins/support/SupportAction.java::Restricted` (89-93) | java | SupportAction (RootAction, urlName "support") via StaplerProxy getTarget(); HTTP request to /support/... reaches getTarget() which checks CREATE_BUNDLE (Support/DownloadBundle) instead of Jenkins.ADMI | 0.85 |

## kimai/kimai

- advisory: GHSA-9w8f-7wgr-2h7g (access_control, CWE-284), origin `?`, ecosystem ?, licence ?
- fix `ff9acab0fc81f0e9490462739ef15fe4ab028ea5`, parent (fix^1) `76e09447c85e762882126b49626a4fe4d93fe8b5`
- advisory title: kimai2 is vulnerable to Improper Access Control

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `kimai-kimai-166480170479d403` | `src/Controller/InvoiceController.php::createInvoiceAction` (166-185) | php | GET /save-invoice/{customer}/{template} (route name invoice_create) in InvoiceController::createInvoiceAction | 0.75 |
| `kimai-kimai-5e04ee92bdb735ea` | `src/Controller/InvoiceController.php::previewAction` (136-165) | php | GET /preview/{customer}/{template} route (invoice_preview) in InvoiceController::previewAction; attacker-controlled source is the {customer} route parameter (Customer entity) and {template} parameter, | 0.85 |

## mage-ai/mage-ai

- advisory: GHSA-c6mm-2g84-v4m7 (access_control, CWE-306), origin `?`, ecosystem ?, licence ?
- fix `f63cd00f6a3be372397d37a4c9a49bfaf50d7650`, parent (fix^1) `e16a64962d540046b1210b5b749897cf600f0ed3`
- advisory title: Mage-ai missing user authentication

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `mage-ai-mage-ai-c9810ee637c308c0` | `mage_ai/server/terminal_server.py::open` (54-93) | python | WebSocket TerminalWebsocketServer.open (terminal_server.py) via /terminals/websocket route; attacker-controlled source: websocket query arguments api_key, token, cwd, term_name | 0.85 |
| `mage-ai-mage-ai-d1ee6d54adc38f57` | `mage_ai/frontend/components/Terminal/index.tsx::Terminal` (43-407) | typescript | Terminal component (mage_ai/frontend/components/Terminal/index.tsx) rendered in the Mage web UI; keyboard input via registerOnKeyDown and sendMessage WebSocket channel | 0.6 |

