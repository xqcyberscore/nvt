###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_wmi_everyone_file-shares.nasl 8897 2018-02-21 09:04:23Z cfischer $
#
# Get Windows File-Shares, shared for Everyone
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# Set in an Workgroup Environment under Windows Vista and greater,
# with enabled UAC this DWORD to access WMI:
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy to 1
#
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

# nb: Keep above the description part as it is used there
include("gos_funcs.inc");
include("version_func.inc");

# nb: includes in the description phase won't work anymore from GOS 4.2.11 (OpenVAS TBD)
# onwards so checking for the defined_func and default to FALSE below if the funcs are undefined
if( defined_func( "get_local_gos_version" ) &&
    defined_func( "version_is_less" ) ) {
  gos_version = get_local_gos_version();
  if( ! strlen( gos_version ) > 0 ||
      version_is_less( version:gos_version, test_version:"4.2.4" ) ) {
    old_routine = TRUE;
  } else {
    old_routine = FALSE;
  }
} else {
  old_routine = FALSE;
}

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96198");
  script_version("$Revision: 8897 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-21 10:04:23 +0100 (Wed, 21 Feb 2018) $");
  script_tag(name:"creation_date", value:"2015-09-08 13:13:18 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows File-Shares, shared for Everyone");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("Windows");
  script_mandatory_keys("WMI/Accessible_Shares", "SMB/password", "SMB/login", "Tools/Present/wmi");
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "2014/gb_ms_wmi_accessible_shares.nasl");

  tag_summary = "Get Windows File-Shares, shared for Everyone.";

  if( old_routine ) {
    script_add_preference(name:"Run routine (please see NOTE)", type:"checkbox", value:"no");

    tag_summary += "

    NOTE: This plugin is using the 'win_cmd_exec' command from openvas-smb which is deploying a
    service 'winexesvc.exe' to the target system. Because of this the plugin is disabled by default
    to avoid modifications on the target system. Please see the script preferences on how to enable this.";
  }

  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");

if( old_routine ) {
  run_script = script_get_preference( "Run routine (please see NOTE)" );
  if( run_script == "no" ) exit( 0 );
}

samba = get_kb_item( "SMB/samba" );
if( samba ) exit( 0 );

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
passwd  = get_kb_item("SMB/password");
shares  = get_kb_item("WMI/Accessible_Shares");

if(!host || !usrname || !passwd){
  exit(0);
}

# nb: wmi_connect and win_cmd_exec needs a different syntax for a domain user
if (domain){
  wmiusrname = domain + '\\' + usrname;
  wincmdexecusrname = domain + '/' + usrname;
} else {
  wmiusrname = usrname;
  wincmdexecusrname = usrname;
}

handle = wmi_connect(host:host, username:wmiusrname, password:passwd);
if(!handle){
  exit(0);
}

query = "select Name from Win32_SystemAccount where SID='S-1-1-0'";

EveryonesName = wmi_query(wmi_handle:handle, query:query);
if (!EveryonesName){
  wmi_close(wmi_handle:handle);
  exit(0);
}

se = split(EveryonesName,keep:0);
se = split(se[1],sep:'|',keep:0);
se = se[1];

sl = split(shares,keep:0);

for(a=1 ;a<max_index(sl); a++){
  READ = NULL;
  CHANGE = NULL;
  FULL = NULL;
  RES = NULL;
  
  s = split(sl[a],sep:'|',keep:0);
  fold = eregmatch(pattern:":", string:s[1]);
  if(fold){
    c = "net share " + s[0];
    val = win_cmd_exec(cmd:c, password:passwd, username:wincmdexecusrname);

    READ = eregmatch(pattern:se + ", READ", string:val);
    CHANGE = eregmatch(pattern:se + ", CHANGE", string:val);
    FULL = eregmatch(pattern:se + ", FULL", string:val);

    if (READ[0]) RES = s[1] +":  " +  READ[0] + "\n";
    if (CHANGE[0]) RES = s[1] +":  " +  CHANGE[0] + "\n";
    if (FULL[0]) RES = s[1] +":  " +  FULL[0] + "\n";

    result = result + RES;
  }
}

if( result ) {
  report = 'The following File-Shares are shared for Everyone:\n' + result;
  log_message(port:0, data:report);
}

wmi_close(wmi_handle:handle);
exit(0);
