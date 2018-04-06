###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sami_ftp_serv_mult_cmd_dos_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Sami FTP Server Multiple Commands Denial of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to deny the service.";
tag_affected = "KarjaSoft Sami FTP Server version 2.0.2 and prior";
tag_insight = "The flaw exists in server, due to improper handling of input passed ot the
  commands (e.g., APPE, CWD, DELE, MKD, RMD, RETR, RNFR, RNTO, SIZE, and STOR).";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.
For updates refer to http://www.karjasoft.com ";
tag_summary = "This host is running Sami FTP Server and is prone to remote denial
  of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800305");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5105", "CVE-2008-5106");
  script_bugtraq_id(27817);
  script_name("Sami FTP Server Multiple Commands Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/488198/100/200/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(get_port_state(port))
{
  banner = get_ftp_banner(port:port);
  if("Sami FTP Server" >!< banner){
    exit(0);
  }

  ftpVer = eregmatch(pattern:"Sami FTP Server ([0-9.]+)", string:banner);
  if(ftpVer != NULL)
  {
    # Grep versions 2.0.2 and prior
    if(version_is_less_equal(version:ftpVer[1], test_version:"2.0.2")){
      security_message(port);
    }
  }
}
