##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_titan_ftp_server_cmd_processing_dos_vuln_900160.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Titan FTP Server 'SITE WHO' Command Remote DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

tag_impact = "Successful exploitation will cause denial of service.
  Impact Level : Application";

tag_solution = "Update to version 6.26.631 or later
  http://www.titanftp.com/download/index.html";

tag_affected = "South River Technologies Titan FTP Server versions prior to 6.26.631";


tag_summary = "The host is running Titan FTP Server and is prone to denial of
  service vulnerability.

  The flaw is due to error in the 'SITE WHO' command processing, which 
  can be exploited to exhaust available CPU resources.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900160");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-23 14:16:10 +0200 (Thu, 23 Oct 2008)");
  script_cve_id("CVE-2008-6082");
 script_bugtraq_id(31757);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Denial of Service");
  script_name("Titan FTP Server 'SITE WHO' Command Remote DoS Vulnerability");

  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6753");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32269/");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port:port);
if("Titan FTP Server" >< banner)
{
  # Grep versions prior to 6.26.631
  if(egrep(pattern:"Titen FTP Server ([0-5](\..*)|6(\.[01]?[0-9]|\.2[0-6])" +
                   "(\.[0-5]?[0-9]?[0-9]?|\.6[0-2][0-9]|\.630))($|[^.0-9])",
            string:banner))
  {
    security_message(port);
    exit(0);
  }
}
