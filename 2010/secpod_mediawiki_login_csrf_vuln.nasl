###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mediawiki_login_csrf_vuln.nasl 5394 2017-02-22 09:22:42Z teissa $
#
# MediaWiki Login CSRF Vulnerability
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

tag_impact = "Successful exploitation will let the attacker cause CSRF attack and gain
  sensitive information.
  Impact Level: Application";
tag_affected = "MediaWiki version prior to 1.15.3
  MediaWiki version prior to 1.16.0beta2";
tag_insight = "The flaw is caused by improper validation of authenticated but unintended
  login attempt that allows attacker to conduct phishing attacks.";
tag_solution = "Upgrade to the latest version of  MediaWiki 1.15.3 or later,
  For updates refer tohttp://www.mediawiki.org";
tag_summary = "This host is running MediaWiki and is prone to Login CSRF
  vulnerability.";

if(description)
{
  script_id(901109);
  script_version("$Revision: 5394 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-22 10:22:42 +0100 (Wed, 22 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2010-1150");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("MediaWiki Login CSRF Vulnerability");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=580418");
  script_xref(name : "URL" , value : "https://bugzilla.wikimedia.org/show_bug.cgi?id=23076");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("version_func.inc");

## Get HTTP Port
wikiPort = get_kb_item("Services/www");
if(!get_port_state(wikiPort)){
  exit(0);
}

## Get version from KB
mediawiki = get_kb_item("MediaWiki/Version");
if(!mediawiki){
  exit(0);
}

if(mediawiki)
{
  ## Grep for affected MediaWiki Versions
  if(version_is_less(version:mediawiki, test_version:"1.15.3") ||
     version_in_range(version:mediawiki, test_version:"1.6", test_version2:"1.16.0.beta2")){
    security_message(wikiPort);
  }
}
