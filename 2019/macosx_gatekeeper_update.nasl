###############################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_gatekeeper_update.nasl 1.0 2019-05-09 16:20:00Z $
#
# Check that Mac OSX Gatekeeper is up-to-date
#
# Authors:
# Daniel Craig <daniel.craig@xqcyber.com>
#
# Copyright:
# Copyright (c) 2017 XQ Digital Resilience Limited
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.300042");
  script_version("$Revision: 1.0 $");
  script_tag(name:"last_modification", value:"$Date: 2019-05-09 16:20:00 +0000 (Thu, 9 May 2019) $");
  script_name('Mac OSX Gatekeeper Update');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 XQ Cyber");
  script_family("Compliance");
  script_dependencies("gather-package-list.nasl", "ssh_authorization.nasl", "global_settings.nasl");
  script_mandatory_keys("login/SSH/success", "ssh/login/osx_name", "ssh/login/osx_version");

  exit(0);
}

include("ssh_func.inc");
include("macosx_update_catalogue.inc");

if( get_kb_item( "global_settings/authenticated_scans_disabled" ) ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if(!sock) exit(0);

ssh_osx_ver = get_kb_item("ssh/login/osx_version");
minimum_version_required(minimum_version:"10.8", current_version:ssh_osx_ver);
update_urls = get_osx_update_urls(version:ssh_osx_ver);

# ditch if we cannot resolve any update urls for this version
if(isnull(update_urls)) exit(0);

# curl the update_ruls for this version of macOS
# look for GatekeeperConfigData.pkm and strip out the <string> and </string> tags.
# Remove newlines and replace them with a space.
gatekeeper_config_data_cmd = string('curl -s '+ update_urls +' | grep "GatekeeperConfigData.pkm"|sed -E \'s@( +|</?string>)@@g\'|sed -E \'s@(\\n)@ @g\' | tr \'\\n\' \' \'');
gatekeeper_config_data_buffer = ssh_cmd_exec(cmd: gatekeeper_config_data_cmd);

if ( gatekeeper_config_data_buffer == "" ) {
	log_message(data:'Could not retrieve config data for gatekeeper');
	exit(0);
}

# curl the urls we received from gatekeeper_config_data_cmd, and grep for the version numbers. Sort them, and get the last one (highest version number)
latest_version_cmd = string('curl -s ' + gatekeeper_config_data_buffer + '|grep -Eo \'version="[0-9]{3,}[.0-9]+"\'|grep -Eo \'[0-9\\.]+\'|sort -n|tail -n1;');
latest_version_buffer = ssh_cmd_exec(cmd: latest_version_cmd);

if ( latest_version_buffer == "" ) {
	log_message(data:latest_version_cmd);
	log_message(data:'Could not determine the latest version of gatekeeper');
	exit(0);
}

# iterate over installed packages that match the Gatekeeper regex
# get the package information awk the version number
# sort them
# get the last one (highest version)
current_version_cmd = string('for i in $(pkgutil --pkgs=".*Gatekeeper.*"); do pkgutil --pkg-info $i | awk \'/version/ {print $2}\'; done|sort -n|tail -n1;');
current_version_buffer = ssh_cmd_exec(cmd: current_version_cmd);

if ( current_version_buffer == "" ) {
	log_message(data:'Could not determine current version of gatekeeper');
	exit(0);
}

# get the status of gatekeeper - either "assessments enabled" or "assessments disabled"
status_cmd = string('spctl --status');
status_buffer = ssh_cmd_exec(cmd: status_cmd);
if ( status_buffer == "" ) {
	log_message(data:'Could not determine the status of gatekeeper');
	exit(0);
}

ssh_close_connection();

# default to out of date
if ( latest_version_buffer == current_version_buffer) {
	version = 'up to date';
} else {
	version = 'out of date';
}

# default to disabled
if ( status_buffer == "assessments enabled" ) {
	enabled = 'enabled';
} else {
	enabled = 'disabled';
}

log_message(data:enabled + '|' + version);
exit(0);
