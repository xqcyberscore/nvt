###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie9_cookie_hijacking_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Internet Explorer Cookie Hijacking Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
##############################################################################

tag_impact = "Successful exploitation will allow remote attackers to read
cookie files of the victim and impersonate users requests.

Impact Level:System/ Application";

tag_affected = "Internet Explorer Version 9.0 and prior.";

tag_insight = "The flaw exists due to the application which does not properly
restrict cross-zone drag-and-drop actions, allows user-assisted remote
attackers to read cookie files via vectors involving an IFRAME element with a
SRC attribute containing an http: URL that redirects to a file: URL.";

tag_solution = "Run Windows Update and update the listed hotfixes or download
and update mentioned hotfixes in the advisory from the below link,
http://www.microsoft.com/technet/security/bulletin/ms11-057.mspx";

tag_summary = "The host is installed with Internet Explorer and is prone to
cookie hijacking vulnerability.

This NVT has been replaced by NVT secpod_ms11-057.nasl
(OID:1.3.6.1.4.1.25623.1.0.902613).";

if(description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.802203");
  script_version("$Revision: 9351 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:43:58 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-2383");
  script_name("Microsoft Internet Explorer Cookie Hijacking Vulnerability");
  script_xref(name : "URL" , value : "http://www.networkworld.com/community/node/74259");
  script_xref(name : "URL" , value : "http://www.theregister.co.uk/2011/05/25/microsoft_internet_explorer_cookiejacking/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-057.nasl.

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for Microsoft Internet Explorer version <= 9.0.8112.16421
if(version_is_less_equal(version:ieVer, test_version:"9.0.8112.16421")){
  security_message(0);
}
