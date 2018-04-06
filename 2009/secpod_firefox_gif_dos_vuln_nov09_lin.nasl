###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_gif_dos_vuln_nov09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Firefox 'GIF' File DoS Vulnerability - Nov09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation could allows remote attacker to cause a vulnerable
  application to crash.
  Impact Level: Application";
tag_affected = "Mozilla Firefox version prior to 3.5.5 on Linux.";
tag_insight = "A NULL pointer dereference error in 'nsGIFDecoder2::GifWrite' function in
  'decoders/gif/nsGIFDecoder2.cpp' in libpr0n, which can be exploited to cause
  application crash via an animated 'GIF' file with a large image size.";
tag_solution = "Upgrade to Firefox version 3.5.5 or later,
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Firefox browser and is prone to Denial
  of Service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900895");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3978");
  script_name("Mozilla Firefox 'GIF' File DoS Vulnerability - Nov09 (Linux)");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=525326");
  script_xref(name : "URL" , value : "https://wiki.mozilla.org/Releases/Firefox_3.5.5/Test_Plan");
  script_xref(name : "URL" , value : "http://hg.mozilla.org/releases/mozilla-1.9.1/rev/edf189567edc");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
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

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer){
  exit(0);
}

# Grep for Firefox version < 3.5.5
if(version_is_less(version:ffVer, test_version:"3.5.5")){
  security_message(0);
}
