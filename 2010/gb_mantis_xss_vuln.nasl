##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_xss_vuln.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# MantisBT Cross-site scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to conduct cross-site scripting
  attacks.
  Impact Level: Application.";
tag_affected = "MantisBT version prior to 1.2.2";

tag_insight = "The application allows remote authenticated users to inject arbitrary web
  script or HTML via an HTML document with a '.gif' filename extension,
  related to inline attachments.";
tag_solution = "Upgrade to MantisBT version 1.2.2 or later
  For updates refer to http://www.mantisbt.org/download.php";
tag_summary = "This host is running MantisBT and is prone to Cross-site scripting
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801449");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-2802");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_name("MantisBT Cross-site scripting Vulnerability");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/blog/?p=113");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/08/03/7");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/08/02/16");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("mantis_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
mantisPort = get_http_port(default:80);
if(!get_port_state(mantisPort)){
  exit(0);
}

## GET the version from KB
mantisVer = get_version_from_kb(port:mantisPort,app:"mantis");

if(mantisVer != NULL)
{
  ## Check for the  MantisBT version
  if(version_is_less(version:mantisVer, test_version:"1.2.2")){
    security_message(mantisPort);
  }
}
