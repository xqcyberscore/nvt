###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_mult_xss_vuln.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# Joomla! Multiple Cross-site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to to inject arbitrary web
  script or HTML via vectors involving 'multiple encoded entities'.
  Impact Level: Application";
tag_affected = "Joomla! versions 1.5.x before 1.5.21";
tag_insight = "The flaws are due to inadequate filtering of multiple encoded entities,
  which could be exploited by attackers to cause arbitrary scripting code to be
  executed by the user's browser in the security context of an affected Web site.";
tag_solution = "Upgrade to Joomla! 1.5.21 or later,
  For updates refer to http://www.joomla.org/download.html";
tag_summary = "This host is running Joomla and is prone to multiple Cross-site
  scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901168");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-3712");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Joomla! Multiple Cross-site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2615");
  script_xref(name : "URL" , value : "http://developer.joomla.org/security/news/9-security/10-core-security/322-20101001-core-xss-vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Get Joomla Version
if(!joomlaVer = get_version_from_kb(port:port, app:"joomla")){
  exit(0);
}

if(!isnull(joomlaVer) && joomlaVer >!< "unknown")
{
  if(version_in_range(version: joomlaVer, test_version:"1.5", test_version2: "1.5.20"))
  {
    security_message(port:port);
    exit(0);
  }
}
