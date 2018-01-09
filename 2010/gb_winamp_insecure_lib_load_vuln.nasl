###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winamp_insecure_lib_load_vuln.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# Winamp Insecure Library Loading Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
code and conduct DLL hijacking attacks via a Trojan horse wnaspi32.dll.

Impact Level: Application.";

tag_affected = "Nullsoft Winamp version 5.581 and prior.";

tag_insight = "The flaw is due to the application loading libraries in an
insecure manner. This can be exploited to load arbitrary libraries by tricking
a user into opening an 'ASX' file located on a remote WebDAV or SMB share.";

tag_solution = "Upgrade to version 5.6 or later,
For updates refer to http://www.winamp.com/media-player";

tag_summary = "This host is installed with Winamp and is prone to insecure
library loading vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801437");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_cve_id("CVE-2010-3137");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Winamp Insecure Library Loading Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41093/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14789/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
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

# Check for version 5.581 => 5.5.8.2975 and prior
if(version_is_less_equal(version:winampVer, test_version:"5.5.8.2975")){
  security_message(0);
}
