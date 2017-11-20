###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssh_authentication_info.nasl 7814 2017-11-17 14:30:20Z cfischer $
#
# SSH Authenticated Scan Info Consolidation
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108162");
  script_version("$Revision: 7814 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-17 15:30:20 +0100 (Fri, 17 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-10-17 10:31:0 +0200 (Tue, 17 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Authenticated Scan Info Consolidation");
  script_category(ACT_END);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");

  script_tag(name:"summary", value:"This script consolidates various technical information about
  authenticated scans via SSH.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("misc_func.inc");

info_array = make_array();
# nb: key is the KB item, value the description used in the report
kb_array = make_array( "ssh/login/uname", "Response to 'uname -a' command",
                       "login/SSH/success", "Login successfull",
                       "no_linux_shell", "Login on a system without common commands like 'cat' or 'find'",
                       "lsc/locate/available", "locate: Command available",
                       "ssh/cmd_exec_error", "Don't prepend '/bin/sh -c' to used commands",
                       "ssh/force/pty", "Commands are send via an pseudoterminal/pty",
                       "ssh/send_extra_cmd", "Send an extra command",
                       "global_settings/ssh/debug", "Debugging enabled within 'Global variable settings'",
                       "Enable/find", "Also use 'find' command to search for Applications enabled within 'Options for Local Security Checks'",
                       "Descend/OFS", "Descend directories on other filesystem enabled within 'Options for Local Security Checks'",
                       "ssh/login/release", "Operating System Key used",
                       "cisco/broken_autocommand", "Misconfigured CISCO device. No autocommand should be configured for the scanning user.",
                       "ssh/restricted_shell", "Login on a system with a restricted shell" );

foreach kb_item( keys( kb_array ) ) {
  if( kb = get_kb_item( kb_item ) ) {
    if( kb == TRUE ) kb = "TRUE";
    if( kb_item == "ssh/send_extra_cmd" ) {
      kb = str_replace( string:kb, find:'\n', replace:"\newline" );
    }
    info_array[kb_array[kb_item] + " (" + kb_item + ")"] = kb;
  } else {
    if( kb_item == "ssh/login/release" ) {
      info_array[kb_array[kb_item] + " (" + kb_item + ")"] = "None/Empty";
    } else {
      info_array[kb_array[kb_item] + " (" + kb_item + ")"] = "FALSE";
      if( kb_item == "lsc/locate/available" ) {
        locate_broken = TRUE;
        reason = get_kb_item( "lsc/locate/broken" );
        if( strlen( reason ) <= 0 ) reason = "Empty/no response (maybe the database is not initialized or locate is not installed)";
        info_array["locate: Response to 'locate -S' command (lsc/locate/broken)"] = reason;
      }
    }
  }
}

info_array["Port used for authenciated scans (kb_ssh_transport())"] = kb_ssh_transport() + "/tcp";
info_array["User used for authenciated scans (kb_ssh_login())"] = kb_ssh_login();

report += text_format_table( array:info_array, columnheader:make_list( "Description (Knowledge base entry)", "Value/Content" ) );
if( locate_broken ) {
  report += '\n\nNOTE: The locate command seems to be unavailable for this user/account/system. ';
  report += "This command is highly recommended for authenticated scans. ";
  report += "Please see the output above for a possible hint / reason why this command is not available.";
}

log_message( port:0, data:report );
exit( 0 );