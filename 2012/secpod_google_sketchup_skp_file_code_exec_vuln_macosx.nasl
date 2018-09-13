###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_sketchup_skp_file_code_exec_vuln_macosx.nasl 11357 2018-09-12 10:57:05Z asteins $
#
# Google SketchUp '.SKP' File Remote Code Execution Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902681");
  script_version("$Revision: 11357 $");
  script_cve_id("CVE-2011-2478");
  script_bugtraq_id(48363);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:57:05 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-05-21 14:56:42 +0530 (Mon, 21 May 2012)");
  script_name("Google SketchUp '.SKP' File Remote Code Execution Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38187");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68147");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/msvr/msvr11-006");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("General");
  script_dependencies("secpod_google_sketchup_detect_macosx.nasl");
  script_require_keys("Google/SketchUp/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause SketchUp to exit
  unexpectedly and execute arbitrary code by tricking a user into opening a
  specially crafted '.SKP' file.");
  script_tag(name:"affected", value:"Google SketchUp version 7.1 Maintenance Release 2 and prior on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an error when handling certain types of invalid
  edge geometry in a specially crafted SketchUp (.SKP) file.");
  script_tag(name:"solution", value:"Upgrade to Google SketchUp version 8.0 or later,
  For updates refer to http://sketchup.google.com/download/index2.html");
  script_tag(name:"summary", value:"This host is installed with Google SketchUp and is prone to
  to remote code execution vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

gsVer = get_kb_item("Google/SketchUp/MacOSX/Version");
if(!gsVer){
  exit(0);
}

if(version_is_less_equal(version:gsVer, test_version:"7.1.6859")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
