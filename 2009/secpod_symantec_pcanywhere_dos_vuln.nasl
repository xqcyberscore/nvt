###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_symantec_pcanywhere_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Symantec pcAnywhere Format String DoS Vulnerability
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

tag_impact = "Allows a malicious user to crash an affected application, creating a denial
  of service condition.
  Impact Level: Application";
tag_affected = "Symantec pcAnywhere version 12.5 and prior on Windows.";
tag_insight = "Issue exists due to improper processing of format strings within '.CHF'
  remote control file names or associated file path.";
tag_solution = "Upgrade to pcAnywhere version 12.5 SP1
  http://www.symantec.com/norton/symantec-pcanywhere";
tag_summary = "This host is installed with Symantec pcAnywhere and is prone
  to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900333");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0538");
  script_bugtraq_id(33845);
  script_name("Symantec pcAnywhere Format String DoS Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34305");
  script_xref(name : "URL" , value : "http://www.layereddefense.com/pcanywhere17mar.html");
  script_xref(name : "URL" , value : "http://securityresponse.symantec.com/avcenter/security/Content/2009.03.17.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_require_keys("Symantec/pcAnywhere/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

pcawVer = get_kb_item("Symantec/pcAnywhere/Ver");
if(!pcawVer){
  exit(0);
}

# Check for Symantec pcAnywhere version <= 12.5 (12.5.0.442)
if(version_is_less_equal(version:pcawVer, test_version:"12.5.0.442")){
  security_message(0);
}
