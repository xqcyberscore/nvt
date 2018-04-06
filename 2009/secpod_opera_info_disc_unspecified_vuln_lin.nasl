###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_info_disc_unspecified_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Opera Information Disclosure and Unspecified Vulnerabilities - (Linux)
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

tag_impact = "Successful exploitation will allow remote attackers to launch cross-site
  scripting attacks or potentially obtain sensitive information and second
  issue has an unknown, but moderate, impact.
  Impact Level: Application";
tag_affected = "Opera version prior to 10.10 on Linux.";
tag_insight = "- Opera stores certain scripting error messages in variables which can be
    read by web sites which can be exploited to execute arbitrary HTML and
    script code in a user's browser session.
  - A vulnerability is due to an unspecified error.";
tag_solution = "Upgrade to Opera 10.10
  http://www.opera.com/download/?custom=yes";
tag_summary = "The host is installed with Opera Web Browser and is prone to
  Information Disclosure and other unspecified vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900987");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4071", "CVE-2009-4072");
  script_bugtraq_id(37089);
  script_name("Opera Information Disclosure and Unspecified Vulnerabilities - (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37469/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unix/1010/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Linux/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

# Check if version is lesser than 10.10
if(version_is_less(version:operaVer, test_version:"10.10")){
  security_message(0);
}
