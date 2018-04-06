###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tfm_mmplayer_m3u_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# TFM MM Player '.m3u' Buffer Overflow Vulnerability - July-09
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation allows the attacker to execute arbitrary
code on the system or cause the application to crash.

Impact Level: Application";

tag_affected = "TFM MMPlayer version 2.0 to 2.2.0.30 on Windows.";

tag_insight = "This flaw is due to improper bounds checking when processing
'.m3u' files and can be exploited via crafted '.m3u' playlist file containing
an overly long string.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with TFM MMPlayer and is prone to stack
based Buffer Overflow bulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900597");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2566");
  script_name("TFM MMPlayer '.m3u' Buffer Overflow Vulnerability - July-09");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_tfm_mmplayer_detect.nasl");
  script_require_keys("TFM/MMPlayer/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35605");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9047");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51442");
  exit(0);
}


include("version_func.inc");

mmplayerVer = get_kb_item("TFM/MMPlayer/Ver");
if(mmplayerVer != NULL)
{
  # Grep for MMPlayer version 2.0 <= 2.2.0.30
  if(version_in_range(version:mmplayerVer, test_version:"2.0",
                                           test_version2:"2.2.0.30")){
    security_message(0);
  }
}
