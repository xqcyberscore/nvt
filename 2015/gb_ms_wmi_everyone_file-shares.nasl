###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_wmi_everyone_file-shares.nasl 3185 2016-04-27 12:26:15Z benallard $
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96198");
  script_version("$Revision: 3185 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-27 14:26:15 +0200 (Wed, 27 Apr 2016) $");
  script_tag(name:"creation_date", value:"2015-09-08 13:13:18 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows File-Shares, shared for Everyone");
  script_summary("Get Windows File-Shares, shared for Everyone. The Script works for Vista and Server 2013 and above.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("Windows");
  script_mandatory_keys("Tools/Present/wmi","SMB/password","SMB/login","WMI/Accessible_Shares");
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "2014/gb_ms_wmi_accessible_shares.nasl");
  script_tag(name : "summary" , value : "Get Windows File-Shares, shared for Everyone");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
shares  = get_kb_item("WMI/Accessible_Shares");

if(!host || !usrname || !passwd){

    exit(0);
}

samba = get_kb_item("SMB/samba");

if(samba){
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

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
    val = win_cmd_exec (cmd:c, password:passwd, username:usrname);

    READ = eregmatch(pattern:se + ", READ", string:val);
    CHANGE = eregmatch(pattern:se + ", CHANGE", string:val);
    FULL = eregmatch(pattern:se + ", FULL", string:val);

    if (READ[0]) RES = s[1] +":  " +  READ[0] + "\n";
    if (CHANGE[0]) RES = s[1] +":  " +  CHANGE[0] + "\n";
    if (FULL[0]) RES = s[1] +":  " +  FULL[0] + "\n";

    result = result + RES;
  }
}
if(result) report = 'The following File-Shares are shared for Everyone:\n' + result;
if(report) log_message(port:port, data:report);

wmi_close(wmi_handle:handle);
exit(0);

