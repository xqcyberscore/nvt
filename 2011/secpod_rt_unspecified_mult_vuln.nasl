###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rt_unspecified_mult_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# RT (Request Tracker) Unspecified Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow an attacker to steal cookie-based
  authentication credentials, compromise the application, access or modify
  data, or exploit latent vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "RT (Request Tracker) versions 2.0.0 through 3.6.10, 3.8.0 through 3.8.9,
  and 4.0.0rc through 4.0.0rc7.";
tag_insight = "- Certain unspecified input is not properly sanitised before being used in
    SQL queries. This can be exploited to manipulate SQL queries by injecting
    SQL code.
  - Certain unspecified input is not properly sanitised before being returned
    to the user. This can be exploited to execute arbitrary HTML and script
    code in a user's browser session in the context of an affected site.";
tag_solution = "Upgrade to RT (Request Tracker) version 3.8.10, 3.6.11 or 4.0.0rc8.
  For updates refer to http://www.bestpractical.com/rt/";
tag_summary = "This host is installed with Request Tracker and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902512");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2011-1686", "CVE-2011-1689");
  script_bugtraq_id(47383);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("RT (Request Tracker) Unspecified Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44189");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66792");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66796");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=696795");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("rt_detect.nasl");
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
if(!get_port_state(port)) {
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

## Check for vulnerable RT versions
if(vers = get_version_from_kb(port:port,app:"rt_tracker"))
{
  if(version_in_range(version:vers, test_version:"3.8.0", test_version2:"3.8.9") ||
     version_in_range(version:vers, test_version:"2.0.0", test_version2:"3.6.10")||
     version_in_range(version:vers, test_version:"4.0.0.rc1", test_version2:"4.0.0.rc7")){
    security_message(port:port);
  }
}
