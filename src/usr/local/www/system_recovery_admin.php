<?php
/*
 * system_recovery_admin.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2025
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

##|+PRIV
##|*IDENT=page-system-recoveryadmin
##|*NAME=System: Recovery Admin
##|*DESCR=Allow access to the 'System: Recovery Admin' page.
##|*MATCH=system_recovery_admin.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("auth.inc");
require_once("functions.inc");
require_once("recovery_admin.inc");
require_once("classes/Form.class.php");

$pgtitle = array(gettext("System"), gettext("User Management"), gettext("Recovery Admin"));
$pglinks = array("", "system_usermanager.php", "@self");

phpsession_begin();
$guiuser = getUserEntry($_SESSION['Username']);
$guiuser = $guiuser['item'];
$read_only = (is_array($guiuser) && userHasPrivilege($guiuser, "user-config-readonly"));
phpsession_end();

$input_errors = array();
$savemsg = null;

$metadata = recovery_admin_get_metadata();

if ($_POST && !$read_only) {
if (empty($_POST['__csrf_magic']) ||
    empty($_SESSION['csrf']['csrfMagicToken']) ||
    !hash_equals($_POST['__csrf_magic'], $_SESSION['csrf']['csrfMagicToken'])) {
	$input_errors[] = gettext("CSRF check failed.");
}

	$formdata = array();
	$formdata['username'] = trim($_POST['username'] ?? '');
	$formdata['auth_backend'] = $_POST['auth_backend'] ?? '';
	$formdata['token_type'] = trim($_POST['token_type'] ?? '');
	$formdata['token_attribute'] = trim($_POST['token_attribute'] ?? '');
	$formdata['token_identifier'] = trim($_POST['token_identifier'] ?? '');
	$formdata['console_access'] = (isset($_POST['console_access']) && $_POST['console_access'] == 'yes');
	$formdata['notes'] = trim($_POST['notes'] ?? '');
	$formdata['created_at'] = $metadata['created_at'] ?? gmdate('c');
	$formdata['updated_at'] = gmdate('c');

	if (empty($formdata['username'])) {
		$input_errors[] = gettext("Username is required.");
	}

	if (empty($formdata['auth_backend'])) {
		$input_errors[] = gettext("Authentication backend is required.");
	}

	if (empty($formdata['token_type'])) {
		$input_errors[] = gettext("Token type is required.");
	}

	if (empty($formdata['token_attribute'])) {
		$input_errors[] = gettext("Token attribute is required.");
	}

	if (empty($formdata['token_identifier'])) {
		$input_errors[] = gettext("Token identifier is required.");
	}

	if (empty($input_errors)) {
		if (!recovery_admin_write_metadata($formdata, null, RECOVERY_ADMIN_METADATA_VERSION)) {
			$input_errors[] = gettext("Failed to persist recovery admin metadata. Check system log for details.");
		} else {
			log_error(gettext("Recovery admin metadata updated via GUI."));
			$savemsg = gettext("Recovery admin settings updated.");
			$metadata = $formdata;
		}
	}
} elseif ($_POST && $read_only) {
	$input_errors[] = gettext("Insufficient privileges to modify recovery admin settings.");
}

$recovery_ready = recovery_admin_storage_ready();

$auth_backends = array('' => gettext('Select an authentication server'));
foreach (auth_get_authserver_list() as $srv) {
	$auth_backends[$srv['name']] = htmlspecialchars($srv['name']);
}

include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Users"), false, "system_usermanager.php");
$tab_array[] = array(gettext("Groups"), false, "system_groupmanager.php");
$tab_array[] = array(gettext("Settings"), false, "system_usermanager_settings.php");
$tab_array[] = array(gettext("Change Password"), false, "system_usermanager_passwordmg.php");
$tab_array[] = array(gettext("Recovery Admin"), true, "system_recovery_admin.php");
$tab_array[] = array(gettext("Authentication Servers"), false, "system_authservers.php");
display_top_tabs($tab_array);

if (!$recovery_ready) {
	print_info_box(gettext("Recovery admin storage has not been initialized yet. It will be created automatically on save."), 'info');
}

if (!empty($savemsg)) {
	print_info_box($savemsg, 'success');
}

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}

$form = new Form(false);
$section = new Form_Section(gettext("Recovery Admin Configuration"));

$section->addInput(new Form_Input(
	"username",
	gettext("Username"),
	'text',
	$metadata['username'] ?? ''
))->setHelp(gettext("Identifier for the recovery admin account. Must match the account in the external authentication system."))
  ->setReadonly($read_only);

$section->addInput(new Form_Select(
	"auth_backend",
	gettext("Authentication Server"),
	$metadata['auth_backend'] ?? '',
	$auth_backends
))->setHelp(gettext("External authentication server used to verify the recovery admin credentials."))
  ->setReadonly($read_only);

$section->addInput(new Form_Input(
	"token_type",
	gettext("Token Type"),
	'text',
	$metadata['token_type'] ?? ''
))->setHelp(gettext("Hardware token or MFA mechanism required for this account (e.g. YubiKey, FIDO2)."))
  ->setReadonly($read_only);

$section->addInput(new Form_Input(
	"token_attribute",
	gettext("Token Attribute"),
	'text',
	$metadata['token_attribute'] ?? ''
))->setHelp(gettext("Name of the RADIUS/LDAP attribute that carries the validated hardware token identifier (case insensitive)."))
  ->setReadonly($read_only);

$section->addInput(new Form_Input(
	"token_identifier",
	gettext("Token Identifier"),
	'text',
	$metadata['token_identifier'] ?? ''
))->setHelp(gettext("Unique identifier for the hardware token, as registered in the external authentication system."))
  ->setReadonly($read_only);

$section->addInput(new Form_Checkbox(
	"console_access",
	gettext("Console Access"),
	gettext("Allow this account to access the local console."),
	!empty($metadata['console_access'])
))->setHelp(gettext("Controls whether the recovery admin may authenticate via the serial/VGA console."))
  ->setReadonly($read_only);

$section->addInput(new Form_Textarea(
	"notes",
	gettext("Notes"),
	$metadata['notes'] ?? ''
))->setHelp(gettext("Optional notes to help operators identify recovery procedures or token storage locations."))
  ->setReadonly($read_only);

$section->addInput(new Form_StaticText(
	gettext("Created"),
	!empty($metadata['created_at']) ? htmlspecialchars($metadata['created_at']) : gettext("Not set")
));

$section->addInput(new Form_StaticText(
	gettext("Last Updated"),
	!empty($metadata['updated_at']) ? htmlspecialchars($metadata['updated_at']) : gettext("Not set")
));

$form->add($section);

$form->addGlobal(new Form_Button(
	'save',
	gettext('Save'),
	null,
	'fa-save'
))->addClass('btn-primary')->setDisabled($read_only);

print($form);

print_info_box(gettext("After updating these settings, ensure the external authentication server and hardware token configuration are consistent. Consider running the recovery admin check from Diagnostics to verify metadata integrity."), 'info');

include("foot.inc");
