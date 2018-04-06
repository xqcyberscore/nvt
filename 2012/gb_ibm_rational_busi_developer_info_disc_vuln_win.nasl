###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_rational_busi_developer_info_disc_vuln_win.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# IBM RBD Web Services Information Disclosure Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to obtain potentially
  sensitive information.
  Impact Level: Application";
tag_affected = "IBM Rational Business Developer version 8.x to 8.0.1.3 on Windows";
tag_insight = "Error exists within web service created with the IBM Rational Business
  Developer product.";
tag_solution = "Upgrade to IBM Rational Business Developer version 8.0.1.4 or later,
  For updates refer to http://www-01.ibm.com/software/awdtools/developer/business/";
tag_summary = "This host is installed with IBM Rational Business Developer and is
  prone information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802685");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-3319");
  script_bugtraq_id(55718);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-12-19 19:17:26 +0530 (Wed, 19 Dec 2012)");
  script_name("IBM RBD Web Services Information Disclosure Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50755/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/78726");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21612314");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialisation
share = "";
filePath = "";
fxPkgPath = "";
rbdExist = "";
rdbLoc = "";
rbdFile = "";
rbdPath = "";
ibmFile = "IBM_Rational_Business_Developer.8.0.0.swtag";
fxPkgVer = [ "8.0.1", "1.8.0.1.1", "2.8.0.1.2", "3.8.0.1.3" ];
fxPkgFile = "IBM_Rational_Business_Developer_Fix_Pack_";
ibmKey = "SOFTWARE\\IBM\\SDP\\license\\35";

## check key existence
if(!registry_key_exists(key:ibmKey)) exit(0);

## get key from registry
rbdExist = registry_get_sz(key:ibmKey, item:"8.0");

## confirm product installation
if (!rbdExist) exit(0);

## built a key to get product installation path
ibmKey = ibmKey - "SDP\\license\\35" + "Installation Manager";

## get install path
rbdPath = registry_get_sz(key:ibmKey, item:"location");

## check the path
if (rbdPath && rbdPath =~ "Installation Manager")
{
  ## build file path 
  rbdPath = rbdPath - "Installation Manager" + "SDP\\rbd\\properties\\version\\";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rbdPath);
  filePath = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",string:rbdPath + ibmFile);
  rbdFile = read_file(share:share, file:filePath, offset:0, count:250);

  ## check the product name in a file
  if (rbdFile && rbdFile =~ "ProductName>IBM Rational Business Developer<" &&
      rbdFile =~ ">8.0.0<")
  {
    ## check fix pack
    foreach fxp (fxPkgVer)
    {
      ## build fix package file path
      fxPkgPath = filePath - ibmFile + fxPkgFile + fxp + ".fxtag";
      rbdFile = read_file(share:share, file:fxPkgPath, offset:0, count:250);

      ## check vulnerable product version
      if (rbdFile && rbdFile =~ "FixName>IBM Rational Business Developer Fix Pack" &&
          rbdFile =~ "FixVersion>8.0.1(.[0-3])?<")
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
