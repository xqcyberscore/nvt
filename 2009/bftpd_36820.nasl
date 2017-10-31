###############################################################################
# OpenVAS Vulnerability Test
# $Id: bftpd_36820.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Bftpd Unspecified Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Bftpd is prone to an unspecified remote denial-of-service
vulnerability.

Successful exploits will cause the affected application to crash,
denying service to legitimate users.

Versions prior to Bftpd 2.4 are vulnerable.";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100320);
 script_version("$Revision: 7573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2009-10-28 11:13:14 +0100 (Wed, 28 Oct 2009)");
 script_bugtraq_id(36820);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2009-4593");

 script_name("Bftpd Unspecified Remote Denial of Service Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36820");
 script_xref(name : "URL" , value : "http://bftpd.sourceforge.net/index.html");
 script_xref(name : "URL" , value : "http://bftpd.sourceforge.net/news.html#032130");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
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

if(!banner = get_ftp_banner(port:ftpPort))exit(0);

if("bftpd" >< banner) {
 
  if(!version = eregmatch(pattern:"220 bftpd ([0-9.]+)", string:banner))exit(0);

  vers = version[1];
  if(!isnull(vers)) {

     if(version_is_less(version:vers, test_version:"2.4")) {
       security_message(port:ftpPort);
       exit(0);
     }  
  }  
}  

exit(0); 

     
