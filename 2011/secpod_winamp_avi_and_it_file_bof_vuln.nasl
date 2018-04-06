###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winamp_avi_and_it_file_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Winamp AVI And IT Files Parsing Buffer Overflow Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  cause a buffer overflow.
  Impact Level: Application.";
tag_affected = "Nullsoft Winamp version 5.622 and prior.";

tag_insight = "Flaws are due to an error in,
  - 'in_avi.dll' plugin when parsing an AVI file with a crafted value for
    the number of streams or the size of the RIFF INFO chunk.
  - 'in_mod.dll' plugin when parsing a crafted song message data in an Impulse
    Tracker (IT) file.";
tag_solution = "Upgrade to Winamp 5.623 or later,
  For updates refer to http://www.winamp.com/media-player";
tag_summary = "This host is installed with Winamp and is prone to buffer overflow
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902652");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-4857", "CVE-2011-3834");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-22 12:11:40 +0530 (Thu, 22 Dec 2011)");
  script_name("Winamp AVI And IT Files Parsing Buffer Overflow Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46882");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51015/info");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Dec/321");
  script_xref(name : "URL" , value : "http://forums.winamp.com/showthread.php?t=332010");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_require_keys("Winamp/Version");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("version_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

# Check for version >= 5.622 build 3189 (5.6.2.3189)
if(version_is_less_equal(version:winampVer, test_version:"5.6.2.3189")){
  security_message(0);
}
