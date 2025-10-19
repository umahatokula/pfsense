<?php
/*
 * recovery_admin.inc
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

require_once("globals.inc");
require_once("util.inc");

define('RECOVERY_ADMIN_DIR', g_get('conf_path') . '/recovery_admin');
define('RECOVERY_ADMIN_METADATA', RECOVERY_ADMIN_DIR . '/metadata.json');
define('RECOVERY_ADMIN_CREDENTIALS', RECOVERY_ADMIN_DIR . '/credentials.hash');
define('RECOVERY_ADMIN_VERSION', RECOVERY_ADMIN_DIR . '/version');
define('RECOVERY_ADMIN_CHECKSUM', RECOVERY_ADMIN_DIR . '/checksums.sha256');
define('RECOVERY_ADMIN_METADATA_VERSION', '1');

/**
 * Track the last error message encountered during recovery admin processing.
 *
 * @param string|null $message Optional message to store.
 * @return string|null Last recorded error.
 */
function recovery_admin_last_error($message = null) {
	static $last_error = null;

	if ($message !== null) {
		$last_error = $message;
	}

	return $last_error;
}

/**
 * Validate recovery admin metadata structure.
 *
 * @param array $metadata Metadata array decoded from JSON.
 * @param array|null $errors Optional array reference to capture error strings.
 * @return bool True when metadata passes validation.
 */
function recovery_admin_validate_metadata(array $metadata, array &$errors = null) {
	$errors = $errors ?? [];
	$required = ['username', 'auth_backend', 'token_type'];

	foreach ($required as $key) {
		if (empty($metadata[$key]) || !is_string($metadata[$key])) {
			$errors[] = sprintf(gettext('Metadata field "%s" must be a non-empty string.'), $key);
		}
	}

	if (!empty($metadata['token_identifier']) && !is_string($metadata['token_identifier'])) {
		$errors[] = gettext('Metadata field "token_identifier" must be a string when present.');
	}

	if (!empty($metadata['token_attribute']) && !is_string($metadata['token_attribute'])) {
		$errors[] = gettext('Metadata field "token_attribute" must be a string when present.');
	}

	if (!empty($metadata['token_identifier']) && empty($metadata['token_attribute'])) {
		$errors[] = gettext('Metadata requires a token attribute when a token identifier is provided.');
	}

	if (isset($metadata['console_access']) && !is_bool($metadata['console_access'])) {
		$errors[] = gettext('Metadata field "console_access" must be boolean when present.');
	}

	if (!empty($metadata['created_at']) && strtotime($metadata['created_at']) === false) {
		$errors[] = gettext('Metadata field "created_at" must be an ISO-8601 timestamp.');
	}

	return empty($errors);
}

/**
 * Return metadata for the recovery admin as an associative array.
 *
 * @return array
 */
function recovery_admin_get_metadata() {
	if (!file_exists(RECOVERY_ADMIN_METADATA)) {
		return [];
	}

	$raw = @file_get_contents(RECOVERY_ADMIN_METADATA);
	if ($raw === false) {
		log_error(gettext("Unable to read recovery admin metadata."));
		return [];
	}

	$data = json_decode($raw, true);
	if (!is_array($data)) {
		log_error(gettext("Recovery admin metadata is not valid JSON."));
		return [];
	}

	return $data;
}

/**
 * Return configured recovery admin username or null.
 *
 * @return string|null
 */
function recovery_admin_username() {
	$metadata = recovery_admin_get_metadata();
	if (empty($metadata['username']) || !is_string($metadata['username'])) {
		return null;
	}

	return $metadata['username'];
}

/**
 * Determine whether provided username matches the recovery admin account.
 *
 * @param string $username Username to evaluate.
 * @return bool
 */
function recovery_admin_matches_username($username) {
	if (empty($username)) {
		return false;
	}

	$target = recovery_admin_username();
	if (empty($target)) {
		return false;
	}

	return strcasecmp($target, $username) === 0;
}

/**
 * Fetch recovery admin metadata auth backend configuration.
 *
 * @return array|null
 */
function recovery_admin_auth_backend() {
	$metadata = recovery_admin_get_metadata();
	if (empty($metadata['auth_backend'])) {
		return null;
	}

	return auth_get_authserver($metadata['auth_backend']);
}

/**
 * Extract attribute value from authentication attribute array.
 *
 * @param array $attributes
 * @param string $attribute_name
 * @return string|null
 */
function recovery_admin_extract_attribute(array $attributes, $attribute_name) {
	if (empty($attribute_name)) {
		return null;
	}

	foreach ($attributes as $key => $value) {
		if (strcasecmp($key, $attribute_name) === 0) {
			if (is_array($value)) {
				$current = reset($value);
				return is_string($current) ? $current : null;
			}

			return is_string($value) ? $value : null;
		}
	}

	return null;
}

/**
 * Attempt to authenticate the recovery admin user using the configured backend.
 *
 * @param string $username
 * @param string $password
 * @param array $attributes
 * @return bool True if authentication succeeds, false otherwise.
 */
function recovery_admin_authenticate($username, $password, array &$attributes = array()) {
	if (!recovery_admin_matches_username($username)) {
		return false;
	}

	recovery_admin_last_error(null);

	$backend = recovery_admin_auth_backend();
	if (empty($backend)) {
		$message = gettext("Recovery admin authentication attempt failed: backend not configured.");
		recovery_admin_last_error($message);
		log_error($message);
		return false;
	}

	$result = authenticate_user($username, $password, $backend, $attributes);
	if (!$result) {
		$message = gettext("Recovery admin authentication attempt rejected by external backend.");
		recovery_admin_last_error($message);
		log_error($message);
		return false;
	}

	$metadata = recovery_admin_get_metadata();
	if (!empty($metadata['token_attribute']) && !empty($metadata['token_identifier'])) {
		$attribute_value = recovery_admin_extract_attribute($attributes, $metadata['token_attribute']);
		if ($attribute_value === null) {
			$message = sprintf(gettext('Recovery admin token attribute "%s" missing from authentication response.'), $metadata['token_attribute']);
			recovery_admin_last_error($message);
			log_error($message);
			return false;
		}

		if (strcasecmp($attribute_value, $metadata['token_identifier']) !== 0) {
			$message = gettext("Recovery admin hardware token validation failed.");
			recovery_admin_last_error($message);
			log_error(sprintf(gettext('Recovery admin token mismatch: expected "%1$s", received "%2$s".'), $metadata['token_identifier'], $attribute_value));
			return false;
		}
	}

	return true;
}

/**
 * Return credential blob for recovery admin if present.
 *
 * @return string|null
 */
function recovery_admin_get_credentials() {
	if (!file_exists(RECOVERY_ADMIN_CREDENTIALS)) {
		return null;
	}

	$raw = @file_get_contents(RECOVERY_ADMIN_CREDENTIALS);
	if ($raw === false) {
		log_error(gettext("Unable to read recovery admin credentials."));
		return null;
	}

	return $raw;
}

/**
 * Return configured schema version for recovery admin metadata.
 *
 * @return string|null
 */
function recovery_admin_get_version() {
	if (!file_exists(RECOVERY_ADMIN_VERSION)) {
		return null;
	}

	$raw = @trim(file_get_contents(RECOVERY_ADMIN_VERSION));
	if ($raw === false) {
		log_error(gettext("Unable to read recovery admin version."));
		return null;
	}

	return $raw;
}

/**
 * Write metadata and optional credential blob using the helper utility.
 *
 * @param array $metadata Associative metadata array.
 * @param string|null $credentials Optional credential data (already encrypted if required).
 * @param string|null $version Optional schema version override.
 * @return bool True on success, false otherwise.
 */
function recovery_admin_write_metadata(array $metadata, $credentials = null, $version = null) {
	global $g;

	$errors = [];
	if (!recovery_admin_validate_metadata($metadata, $errors)) {
		foreach ($errors as $error) {
			log_error($error);
		}
		return false;
	}

	$tmp_meta = tempnam($g['tmp_path'], 'recovery_meta_');
	if ($tmp_meta === false) {
		log_error(gettext("Unable to allocate temporary file for recovery admin metadata."));
		return false;
	}

	$encode_flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT;
	$encoded = json_encode($metadata, $encode_flags);
	if ($encoded === false) {
		@unlink($tmp_meta);
		log_error(gettext("Unable to encode recovery admin metadata as JSON."));
		return false;
	}

	if (@file_put_contents($tmp_meta, $encoded) === false) {
		@unlink($tmp_meta);
		log_error(gettext("Unable to write recovery admin metadata temporary file."));
		return false;
	}

	$tmp_credentials = null;
	if ($credentials !== null) {
		$tmp_credentials = tempnam($g['tmp_path'], 'recovery_creds_');
		if ($tmp_credentials === false) {
			@unlink($tmp_meta);
			log_error(gettext("Unable to allocate temporary file for recovery admin credentials."));
			return false;
		}
		if (@file_put_contents($tmp_credentials, $credentials) === false) {
			@unlink($tmp_meta);
			@unlink($tmp_credentials);
			log_error(gettext("Unable to write recovery admin credentials temporary file."));
			return false;
		}
	}

	$cmd = "/usr/local/sbin/recovery_admin_update --metadata " . escapeshellarg($tmp_meta);

	if ($tmp_credentials !== null) {
		$cmd .= " --credentials " . escapeshellarg($tmp_credentials);
	}

	if (!empty($version)) {
		$cmd .= " --version " . escapeshellarg($version);
	} else {
		$cmd .= " --version " . escapeshellarg(RECOVERY_ADMIN_METADATA_VERSION);
	}

	$output = [];
	$ret = mwexec($cmd, $output);

	@unlink($tmp_meta);
	if ($tmp_credentials !== null) {
		@unlink($tmp_credentials);
	}

	if ($ret !== 0) {
		log_error(sprintf(gettext("Failed to update recovery admin metadata (exit %s): %s"),
			$ret,
			implode("\n", $output)));
		return false;
	}

	return true;
}

/**
 * Ensure recovery admin storage has been initialized.
 *
 * @return bool True if directory and metadata file (if present) exist.
 */
function recovery_admin_storage_ready() {
	return is_dir(RECOVERY_ADMIN_DIR);
}
