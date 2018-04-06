###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sdp_downloader_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# SDP Downloader ASX File Heap Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
##############################################################################

tag_impact = "Successful exploits will allow attackers to execute arbitrary
code and can cause application crash via a long .asf URL.

Impact Level: Application";

tag_affected = "SDP Downloader version 2.3.0 and prior";

tag_insight = "A boundary error exists while processing an HREF attribute of a
REF element in ASX files, due to which application fails to check user supplied
input before copying it into an insufficiently sized buffer.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with SDP Downloader and is prone to
Buffer Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900642");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1627");
  script_bugtraq_id(34712);
  script_name("SDP Downloader ASX File Heap Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34883");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8536");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1171");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_sdp_downloader_detect.nasl");
  script_require_keys("SDP/Downloader/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

sdpVer = get_kb_item("SDP/Downloader/Ver");

if(sdpVer != NULL)
{
  if(version_is_less_equal(version:sdpVer,test_version:"2.3.0")){
    security_message(0);
  }
}
