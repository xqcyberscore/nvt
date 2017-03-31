###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gather_windows_uptime.nasl 5486 2017-03-04 18:08:45Z cfi $
#
# Gather uptime from windows remote host
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.96175");
  script_version("$Revision: 5486 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-04 19:08:45 +0100 (Sat, 04 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-26 09:31:15 +0100 (Tue, 26 Jan 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gather Windows uptime");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "os_detection.nasl");
  script_mandatory_keys("Tools/Present/wmi", "SMB/password", "SMB/login", "Host/runs_windows");

  script_tag(name:"summary" , value:"This script attempts to gather the 'uptime' from a windows host and stores the results in the KB.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");

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

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  exit(0);
}

query = "select LastBootUpTime from Win32_OperatingSystem";
wmidata = wmi_query(wmi_handle:handle, query:query);

if(wmidata)
{

  wmiuptime = split(wmidata,keep:0);
  uptime_match = eregmatch( pattern:'^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})', string: wmiuptime[1] );
  if( isnull( uptime_match[0] ) ) exit();
  uptime = mktime( sec:uptime_match[6], min:uptime_match[5], hour:uptime_match[4], mday:uptime_match[3], mon:uptime_match[2], year: uptime_match[1] );
  register_host_detail( name:"uptime", value:uptime );
  set_kb_item( name:"Host/uptime", value:uptime );
}

wmi_close(wmi_handle:handle);
exit( 0 );
