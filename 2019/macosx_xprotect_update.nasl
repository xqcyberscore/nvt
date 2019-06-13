###############################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_xprotect_update.nasl 1.0 2019-02-07 16:20:00Z $
#
#
# Note:
#
# Authors:
# Stephen Penn <stephen.penn@xqcyber.com>
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
  script_oid("1.3.6.1.4.1.25623.1.1.300041");
  script_version("$Revision: 1.0 $");
  script_tag(name:"last_modification", value:"$Date: 2019-05-10 16:00:00 +0100 (fri, 30 may 2019) $");
  script_tag(name:"creation_date", value:"2019-05-10 16:00:00 +0100 (fri, 30 may 2019)");
  script_name("Apple MacOSX Xprotect Update check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 XQ Cyber");
  script_family("Compliance");
  script_dependencies("gather-package-list.nasl", "ssh_authorization.nasl", "global_settings.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");

  exit(0);
}

include("ssh_func.inc");
include("macosx_update_catalogue.inc");

if( get_kb_item( "global_settings/authenticated_scans_disabled" ) ) exit( 0 );

# Check if port for us is known
port = get_preference( "auth_port_ssh" );
if( ! port ){
	port = get_kb_item( "Services/ssh" );
}
if( ! port ){
	port = 22;
}

if( get_kb_item( "global_settings/authenticated_scans_disabled" ) ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if(!sock) exit(0);

ssh_osx_ver = get_kb_item("ssh/login/osx_version");

minimum_version_required(minimum_version:"10.14", current_version:ssh_osx_ver);

update_urls = get_osx_update_urls(version:ssh_osx_ver);

# ditch if we cannot resolve any update urls for this version
if(update_urls == "unknown") {
	log_message(data:string("Unable to find an Update Catalog URL for the following version of macOS: ", ssh_osx_ver));
	exit(0);
}

#Retrieve XProtect config data
xprotect_config_data_cmd = string('curl -s '+ update_urls +' |grep "XProtectPlistConfigData.pkm"|sed -E \'s@( +|</?string>)@@g\'');
xprotect_config_data_buffer = ssh_cmd_exec(cmd: xprotect_config_data_cmd);

if(xprotect_config_data_buffer == "") {
    log_message(data:"Could not retrieve config data for XProtect. Trying again might get it work.");
    exit(0);
}

#Retrieve XProtect latest version
xprotect_latest_version_cmd = string('curl -s ' + xprotect_config_data_buffer + '|grep -Eo \'version="[0-9]{3,}\\.[0-9\\.]+"\'|grep -Eo \'[0-9\\.]+\'|sort -n|tail -n1;');
xprotect_latest_version_buffer = ssh_cmd_exec(cmd: xprotect_latest_version_cmd);

if(xprotect_latest_version_buffer == "") {
    log_message(data: xprotect_latest_version_cmd);
    log_message(data: "Could not determine the latest version of XProtect");
    exit(0);
}

#Retrieve XProtect current version
xprotect_current_version_cmd = string('for i in $(pkgutil --pkgs=".*XProtect.*"); do pkgutil --pkg-info $i | awk \'/version/ {print $2}\'; done|sort -n|tail -n1;');
xprotect_current_version_buffer = ssh_cmd_exec(cmd: xprotect_current_version_cmd);

if(xprotect_current_version_buffer == "") {
    log_message(data: "Could not determine the current version of XProtect");
    exit(0);
}

xprotect_installed_cmd = string('pkgutil --pkgs | grep XProtect | wc -l');
xprotect_installed_cmd_buffer = ssh_cmd_exec(cmd: xprotect_installed_cmd);

ssh_close_connection();

if ( xprotect_latest_version_buffer == xprotect_current_version_buffer) {
	version = 'up to date';
} else {
	version = 'out of date';
}

if ( int(xprotect_installed_cmd_buffer) > 0 ) {
	is_installed = 'installed';
} else {
	is_installed = 'not installed';
}

log_message(data:is_installed + '|' + version);

exit(0);
