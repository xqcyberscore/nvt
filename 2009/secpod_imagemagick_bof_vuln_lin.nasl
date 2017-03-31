###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_imagemagick_bof_vuln_lin.nasl 5055 2017-01-20 14:08:39Z teissa $
#
# ImageMagick Buffer Overflow Vulnerability (Linux)
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

tag_impact = "Attackers can exploit this issue by executing arbitrary code via a crafted
  TIFF files in the context of an affected application.
  Impact Level: Application";
tag_affected = "ImageMagick version prior to 6.5.2-9 on Linux.";
tag_insight = "The flaw occurs due to an integer overflow error within the 'XMakeImage()'
  function in magick/xwindow.c file while processing malformed TIFF files.";
tag_solution = "Upgrade to ImageMagick version 6.5.2-9 or later.
  http://www.imagemagick.org/script/download.php";
tag_summary = "The host is installed with ImageMagick and is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900565");
  script_version("$Revision: 5055 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-20 15:08:39 +0100 (Fri, 20 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1882");
  script_bugtraq_id(35111);
  script_name("ImageMagick Buffer Overflow Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35216/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_imagemagick_detect_lin.nasl");
  script_require_keys("ImageMagick/Lin/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

imageVer = get_kb_item("ImageMagick/Lin/Ver");
if(!imageVer){
  exit(0);
}

if(version_is_less(version:imageVer, test_version:"6.5.2.9")){
  security_message(0);
}
