###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_titan_ftp_server_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# TitanFTP Server Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the attacker cause denial of service to
  the application by sending crafted requests to the FTP Server.";
tag_affected = "TitanFTP Server version prior to 6.26.631 on Windows.";
tag_insight = "Error exists while processing the SITE WHO command on FTP service which
  in causes extensive usages of CPU resources.";
tag_solution = "Upgrade to the latest version 6.26.631 or later.
  http://www.southrivertech.com/download/index.html";
tag_summary = "This host is running TitanFTP Server and is prone to Denial of
  Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800237");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6082");
  script_bugtraq_id(31757);
  script_name("TitanFTP Server Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32269");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6753");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_titan_ftp_detect.nasl", "find_service.nasl");
  script_require_keys("TitanFTP/Server/Ver");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  exit(0);
}

titanVer = get_kb_item("TitanFTP/Server/Ver");
if(!titanVer){
  exit(0);
}

# Grep for TitanFTP Server version 6.26.630 or prior.
if(version_is_less_equal(version:titanVer, test_version:"6.26.630")){
  security_message(ftpPort);
}
