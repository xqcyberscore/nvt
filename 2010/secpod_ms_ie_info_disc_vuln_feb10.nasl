###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_info_disc_vuln_feb10.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# Microsoft Internet Explorer Information Disclosure Vulnerability Feb10
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation allows attackers to obtain sensitive information via
a crafted stylesheet document.

Impact Level: Application.";
tag_affected = "Microsoft Internet Explorer version 8 and prior on Windows";
tag_insight = "The flaw exists while handling malformed stylesheet document with incorrect
  MIME type. Microsoft Internet Explorer permits cross-origin loading of CSS
  stylesheets even when the stylesheet download has an incorrect MIME type.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";
tag_summary = "This host has Internet Explorer installed and is prone to Information
Disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900741");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0652");
  script_name("Microsoft Internet Explorer Information Disclosure Vulnerability Feb10");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=9877");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(isnull(ieVer)){
  exit(0);
}

## Check for IE version less or equal 8.0.6001.18702
if(version_is_less_equal(version:ieVer, test_version:"8.0.6001.18702")){
  security_message(0);
}

