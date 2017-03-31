###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_wmi_accessible_shares.nasl 5486 2017-03-04 18:08:45Z cfi $
#
# Get Windows shares over WMI
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96199");
  script_version("$Revision: 5486 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-04 19:08:45 +0100 (Sat, 04 Mar 2017) $");
  script_tag(name:"creation_date", value:"2014-03-12 09:32:24 +0200 (Wed, 12 Mar 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows Shares over WMI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "os_detection.nasl");
  script_mandatory_keys("Tools/Present/wmi", "SMB/password", "SMB/login", "Host/runs_windows");

  script_tag(name:"summary", value:"Get Windows Shares over WMI");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");

if( host_runs( "Windows" ) != "yes" ) exit( 0 );

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");

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

query = "select Name, Path from Win32_share";

sharelist = wmi_query(wmi_handle:handle, query:query);

if (!sharelist){
  wmi_close(wmi_handle:handle);
  exit(0);
}

set_kb_item(name:"WMI/Accessible_Shares", value:sharelist);

report = 'The following shares were found\n' + sharelist;
log_message(port:port, data:report);

wmi_close(wmi_handle:handle);
exit(0);

