###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netpbm_xpmtoppm_bof_vuln.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# NetPBM 'xpmtoppm' Converter Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Apply the patch or upgrade to NetPBM 10.47.07
  For updates refer to http://sourceforge.net/projects/netpbm/files/
  http://netpbm.svn.sourceforge.net/viewvc/netpbm/stable/converter/ppm/xpmtoppm.c?view=patch&r1=995&r2=1076&pathrev=1076

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation allows attackers to crash an affected application or
  execute arbitrary code by tricking a user into converting a malicious image.
  Impact Level: Application.";
tag_affected = "NetPBM versions prior to 10.47.07";
tag_insight = "The flaw is due a buffer overflow error in the 'converter/ppm/xpmtoppm.c'
  converter when processing malformed header fields of 'X PixMap' (XPM) image
  files.";
tag_summary = "This host is installed with NetPBM and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800471");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4274");
  script_bugtraq_id(38164);
  script_name("NetPBM 'xpmtoppm' Converter Buffer Overflow Vulnerability");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56207");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0358");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=546580");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_netpbm_detect.nasl");
  script_family("Buffer overflow");
  script_require_keys("NetPBM/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

netpbmVer = get_kb_item("NetPBM/Ver");
if(netpbmVer)
{
  # NetPBM version 10.47.07(10.47.7)
  if(version_is_less(version:netpbmVer, test_version:"10.47.7")){
    security_message(0);
  }
}
