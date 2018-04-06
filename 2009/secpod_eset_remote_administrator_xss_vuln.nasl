##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_eset_remote_administrator_xss_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# ESET Remote Administrator XSS Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful explotiation will allow the attacker to execute arbitrary
  code in the scope of the application and can compromise the way the site is
  rendered to the user.
  Impact Level: Application";
tag_affected = "ESET Remote Administrator version prior to 3.0.105 on Windows.";
tag_insight = "This vulnerability exists in the Additional Report Settings interface which
  fails to properly sanitize user supplied input before using it in dynamically
  generated content. As a result the host becomes vulnerable to arbitrary web
  script or HTML code injection.";
tag_solution = "Upgrade to the version 3.0.105,
  http://www.eset.eu/products/eset-remote-administrator-3";
tag_summary = "This host is running ESET Remote Administrator and is prone
  to remote Cross-Site Scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900509");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_cve_id("CVE-2009-0548");
  script_bugtraq_id(33633);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ESET Remote Administrator XSS Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33805");
  script_xref(name : "URL" , value : "http://www.eset.eu/support/changelog-eset-remote-administrator-3");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_eset_remote_administrator_detect.nasl");
  script_mandatory_keys("ESET/RemoteAdmin/Console_or_Server/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

esetConsVer = get_kb_item("ESET/RemoteAdmin/Console/Ver");
esetServVer = get_kb_item("ESET/RemoteAdmin/Server/Ver");

if((esetConsVer != NULL) || (esetServVer != NULL))
{
  if(version_is_less(version:esetConsVer, test_version:"3.0.105") ||
     version_is_less(version:esetServVer, test_version:"3.0.105")){
    security_message(0);
  }
}
