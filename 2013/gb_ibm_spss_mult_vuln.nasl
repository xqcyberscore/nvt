###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_spss_mult_vuln.nasl 3557 2016-06-20 08:07:14Z benallard $
#
# IBM SPSS SamplePower Multiple Vulnerabilities (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application using the ActiveX control. Failed
  attempts will likely result in denial of service conditions.
  Impact Level: System/Application";

tag_affected = "IBM SPSS SamplePower version 3.0 and prior";
tag_insight = "Multiple flaws due to,
  - Unspecified error in the vsflex7l ActiveX control.
  - Unspecified flaw in the olch2x32 ActiveX control.
  - Error when handling the 'ComboList' or 'ColComboList' in Vsflex8l
    ActiveX control.
  - Error when handling the 'TabCaption' buffer in c1sizer ActiveX control.";
tag_solution = "Upgrade to IBM SPSS SamplePower version 3.0 FP1 (3.0.0.1) or later,
  For updates refer to http://www.ibm.com";
tag_summary = "This host is installed with IBM SPSS SamplePower and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(803398);
  script_version("$Revision: 3557 $");
  script_cve_id("CVE-2012-5947", "CVE-2012-5946", "CVE-2012-5945", "CVE-2013-0593");
  script_bugtraq_id(59556, 59559, 59557, 59527);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 10:07:14 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2013-05-08 11:50:37 +0530 (Wed, 08 May 2013)");
  script_name("IBM SPSS SamplePower Multiple Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53234");
  script_xref(name : "URL" , value : "http://www.ibm.com/support/docview.wss?uid=swg21635476");
  script_xref(name : "URL" , value : "http://www.ibm.com/support/docview.wss?uid=swg21635515");
  script_xref(name : "URL" , value : "http://www.ibm.com/support/docview.wss?uid=swg21635511");
  script_xref(name : "URL" , value : "http://www.ibm.com/support/docview.wss?uid=swg21635503");
  script_summary("Check for the vulnerable version of IBM SPSS SamplePower");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ibm_spss_sample_power_detect_win.nasl");
  script_mandatory_keys("IBM/SPSS/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Variable Initialization
version = "";

## Get version from KB
version = get_kb_item("IBM/SPSS/Win/Ver");
if(version)
{
  ## Check for IBM SPSS SamplePower 3.0.0 or prior
  if(version_is_less_equal(version:version, test_version:"3.0.0"))
  {
    security_message(0);
    exit(0);
  }
}
