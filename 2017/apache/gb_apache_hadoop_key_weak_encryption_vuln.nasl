###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_hadoop_key_weak_encryption_vuln.nasl 7747 2017-11-14 06:11:31Z santu $
#
# Apache Hadoop Weak Key Encryption Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
# 
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:hadoop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811969");
  script_version("$Revision: 7747 $");
  script_cve_id("CVE-2012-4449");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-11-14 07:11:31 +0100 (Tue, 14 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-08 11:34:54 +0530 (Wed, 08 Nov 2017)");
  script_name("Apache Hadoop Weak Key Encryption Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Apache Hadoop
  and is prone to a weak key encryption vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in an unknown
  function of the component 'Kerberos Security Feature'.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to crack secret keys via a brute-force attack.

  Impact Level: Application");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Apache Hadoop before 0.23.4, 1.x before 1.0.4,
  and 2.x before 2.0.2");

  script_tag(name:"solution", value:"Upgrade to Apache Hadoop version 0.23.4 or
  1.0.4 or 2.0.2 or later. For updates refer to http://www.hadoop.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://vuldb.com/de/?id.108783");
  script_xref(name:"URL", value:"https://www.cloudera.com/documentation/other/security-bulletins/topics/csb_topic_1.html#topic_1_0");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");
  script_require_ports("Services/www", 50070);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

hadoopPort = "";
hadoopVer = "";

if(!hadoopPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
hadoopVer = infos['version'];
hadoopPath = infos['location'];

if(hadoopVer =~ "^(2\.0)" && version_is_less(version:hadoopVer, test_version:"2.0.2")){
  fix = "2.0.2";
}

else if(version_in_range(version:hadoopVer, test_version:"1.0", test_version2:"1.0.3")){
  fix = "1.0.4";
}

else if(version_is_less(version:hadoopVer, test_version:"0.23.4")){
  fix = "0.23.4";
}

if(fix)
{
  report = report_fixed_ver(installed_version:hadoopVer, fixed_version:fix, install_path:hadoopPath);
  security_message(data:report, port:hadoopPort);
  exit(0);
}
exit(0);
