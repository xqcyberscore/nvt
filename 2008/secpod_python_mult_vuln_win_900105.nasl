##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_python_mult_vuln_win_900105.nasl 11570 2018-09-24 11:54:11Z cfischer $
#
# Python Multiple Vulnerabilities (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900105");
  script_version("$Revision: 11570 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-24 13:54:11 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_bugtraq_id(30491);
  script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_name("Python Multiple Vulnerabilities (Windows)");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://bugs.python.org/issue2588");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2589");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2620");

  script_tag(name:"summary", value:"The host is installed with Python, which is prone to multiple
   vulnerabilities.");

  script_tag(name:"insight", value:"The flaws exist due to integer overflow in,

  - hashlib module, which can lead to an unreliable cryptographic digest
  results.

  - the processing of unicode strings.

  - the PyOS_vsnprintf() function on architectures that do not have a
  vsnprintf() function.

  - the PyOS_vsnprintf() function when passing zero-length strings can
  lead to memory corruption.");

  script_tag(name:"affected", value:"Python 2.5.2 and prior on Linux (All).");

  script_tag(name:"solution", value:"Fix is available in the SVN repository,
  http://svn.python.org");

  script_tag(name:"impact", value:"Successful exploitation could potentially causes attackers to
  execute arbitrary code or create a denial of service condition.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)){

  pyName = registry_get_sz(key:key + entry, item:"DisplayName");

  if(pyName && "Python" >< pyName) {

    if(egrep(pattern:"Python ([01]\..*|2\.([0-4]\..*|5\.[0-2]))$", string:pyName)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
    exit(99);
  }
}

exit(0);