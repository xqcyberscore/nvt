###############################################################################
# OpenVAS Vulnerability Test
# $Id: TurboFTP_37726.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# TurboFTP 'DELE' FTP Command Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "TurboFTP is prone to a remote buffer-overflow vulnerability.

An attacker can exploit this issue to execute arbitrary code within
the context of the affected application. Failed exploit attempts will
result in a denial-of-service condition.

TurboFTP 1.00.712 is vulnerable; prior versions may also be affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100448);
 script_version("$Revision: 7573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-01-14 12:06:50 +0100 (Thu, 14 Jan 2010)");
 script_bugtraq_id(37726);
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

 script_name("TurboFTP 'DELE' FTP Command Remote Buffer Overflow Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37726");
 script_xref(name : "URL" , value : "http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-004-turboftp-server-1-00-712-dos/");
 script_xref(name : "URL" , value : "http://www.turboftp.com/");
 script_xref(name : "URL" , value : "http://www.tbsoftinc.com/tbserver/turboftp-server-releasenotes.htm");
 exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(get_kb_item('ftp/'+ftpPort+'/broken'))exit(0);

if(!get_port_state(ftpPort)){
  exit(0);
}

ftpbanner = get_ftp_banner(port:ftpPort);

if("TurboFTP" >!< ftpbanner)exit(0);

version = eregmatch(pattern: "220 TurboFTP Server ([0-9.]+)", string: ftpbanner);
if(isnull(version[1]))exit(0);

if(version_is_equal(version: version[1], test_version: "1.00.712")) {
 security_message(port: ftpPort);
 exit(0);
}  

exit(0); 

     
