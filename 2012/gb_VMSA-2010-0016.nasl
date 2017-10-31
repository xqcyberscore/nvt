###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2010-0016.nasl 7583 2017-10-26 12:07:01Z cfischer $
#
# VMSA-2010-0016 VMware ESXi and ESX third party updates for Service Console and Likewise components
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "The remote ESXi is missing one or more security related Updates from VMSA-2010-0016.

Summary

ESX Service Console OS (COS) kernel update, and Likewise packages 
updates.

Relevant releases

  VMware ESXi 4.1 without patch ESXi410-201010401-SG 
  VMware ESX 4.1 without patches ESX410-201010401-SG, ESX410-201010419-SG                   
  VMware ESX 4.0 without patch ESX400-201101401-SG
  
Problem Description

a. Service Console OS update for COS kernel   
   This patch updates the service console kernel to fix multiple
   security issues.

b. Likewise package updates
   Updates to the likewisekrb5, likewiseopenldap, likewiseopen,
   and pamkrb5 packages address several security issues.";

tag_solution = "Apply the missing patch(es).";

if (description)
{
 script_id(103449);
 script_cve_id("CVE-2010-0415","CVE-2010-0307","CVE-2010-0291","CVE-2010-0622","CVE-2010-1087","CVE-2010-1437","CVE-2010-1088","CVE-2009-0844","CVE-2009-0845","CVE-2009-0846","CVE-2009-4212","CVE-2010-1321");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 7583 $");
 script_name("VMSA-2010-0016 VMware ESXi and ESX third party updates for Service Console and Likewise components");


 script_tag(name:"last_modification", value:"$Date: 2017-10-26 14:07:01 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2012-03-15 16:13:01 +0100 (Thu, 15 Mar 2012)");
 script_category(ACT_GATHER_INFO);
 script_family("VMware Local Security Checks");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_vmware_esxi_init.nasl");
 script_mandatory_keys("VMware/ESXi/LSC","VMware/ESX/version");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2010-0016.html");
 exit(0);
}

include("version_func.inc"); # Used in _esxi_patch_missing()
include("vmware_esx.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-201010401-SG");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_message(port:0);
  exit(0);

}

exit(99);
