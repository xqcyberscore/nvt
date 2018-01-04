###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_weborf_range_dos_vuln.nasl 8269 2018-01-02 07:28:22Z teissa $
#
# Weborf 'Range' Header Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to cause a denial of service.
  Impact Level: Application";
tag_affected = "Galileo Students Team Weborf version prior to 0.12.1";
tag_insight = "The flaw is caused by an error when processing malicious HTTP headers.
  By sending a specially-crafted Range header, a remote attacker could
  exploit this vulnerability to cause the application to crash.";
tag_solution = "Upgrade to Galileo Students Team Weborf version 0.12.1 or later,
  For updates refer to http://galileo.dmi.unict.it/wiki/weborf/doku.php";
tag_summary = "This host is running Weborf webserver and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801222");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-2262");
  script_bugtraq_id(40575);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Weborf 'Range' Header Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59135");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40051");
  script_xref(name : "URL" , value : "http://galileo.dmi.unict.it/wiki/weborf/doku.php?id=news:released_0.12.1");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_weborf_webserver_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get version from KB
ver = get_kb_item("www/" + port + "/Weborf");
if(ver != NULL)
{
  ## Check for Weborf Version 0.12.1
  if(version_is_less(version:ver, test_version:"0.12.1")) {
     security_message(port);
  }
}

