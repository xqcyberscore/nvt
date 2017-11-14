###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_prdts_detect_win.nasl 7699 2017-11-08 12:10:34Z santu $
#
# Sun Java Products Version Detection (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800383");
  script_version("$Revision: 7699 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 13:10:34 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Sun Java Products Version Detection (Windows)");

  script_tag(name:"summary", value:"Detection of installed version of Java Products.

  The script logs in via smb, searches for Java Products in the registry and
  gets the version from 'Version' string in registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable initialization
java_name = "";
jdk_name = "";
keys = "";
jrVer = "";
jdVer = "";
wsVer = "";
jreKey = "";
jreVer = "";
jdkKey = "";
jdkVer = "";
JreTmpkey = "";
JdkTmpkey = "";
osArch = "";
osArch = "";

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}


if("x86" >< osArch){
  adkeylist = make_list("SOFTWARE\JavaSoft\Java Runtime Environment\",
                        "SOFTWARE\JavaSoft\JRE\");
}

## Check for 64 bit platform
else if("x64" >< osArch)
{
  adkeylist =  make_list("SOFTWARE\JavaSoft\Java Runtime Environment\",
                         "SOFTWARE\JavaSoft\JRE\",
                         "SOFTWARE\Wow6432Node\JavaSoft\Java Runtime Environment\",
                         "SOFTWARE\Wow6432Node\JavaSoft\JRE\");
}

foreach jreKey (adkeylist)
{
  # Java Runtime Environment
  if(registry_key_exists(key:jreKey))
  {
    keys = registry_enum_keys(key:jreKey);
    foreach item (keys)
    {
      ##For latest Java Versions
      if("JRE" >< jreKey && item =~ "^9")
      {
        pattern = "([0-9.]+)";
        flagjre9 = TRUE;
      } else {
        pattern = "([0-9.]\.[0-9]\.[0-9._]+)";
      }

      jreVer = eregmatch(pattern:pattern, string:item);
      if(jreVer[1])
      {
         JreTmpkey =  jreKey + "\\"  + jreVer[1];
         path = registry_get_sz(key:JreTmpkey, item:"JavaHome");
         if(!path){
           path = "Could not find the install path from registry";
         }


         if(jreVer[1] != NULL)
         {
            set_kb_item(name:"Sun/Java/JRE/Win/Ver", value:jreVer[1]);
            replace_kb_item(name:"Sun/Java/JDK_or_JRE/Win/installed", value:TRUE);
            replace_kb_item(name:"Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value:TRUE);
            if(flagjre9)
            {
              jreVer_or = jreVer[1] ;
              ##Reset Flag
              flagjre9 = FALSE ;
            } else
            {
              jrVer = ereg_replace(pattern:"_|-", string:jreVer[1], replace: ".");

              jreVer1 = eregmatch(pattern:"([0-9]+\.[0-9]+\.[0-9]+)(\.([0-9]+))?", string:jrVer);
              if(jreVer1[1] && jreVer1[3]){
                jreVer_or = jreVer1[1] + ":update_" + jreVer1[3];
              } else if (jreVer1[1]){
                jreVer_or = jreVer1[1];
              }
            }
            if(version_is_less(version:jrVer, test_version:"1.4.2.38") ||
               version_in_range(version:jrVer, test_version:"1.5", test_version2:"1.5.0.33") ||
               version_in_range(version:jrVer, test_version:"1.6", test_version2:"1.6.0.18"))
            {
               java_name = "Sun Java JRE 32-bit";
               ## set the CPE "cpe:/a:sun:jre:" if JRE belongs the above version range
               ## (Before Oracles acquisition of Sun)
               ## build cpe and store it as host_detail
               cpe = build_cpe(value:jreVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jre:");
                 if(isnull(cpe))
               cpe="cpe:/a:sun:jre";

            }
            else
            {
               java_name = "Oracle Java JRE 32-bit";
               ## set the CPE "cpe:/a:oracle:jre:" for recent versions of JRE
               ## (After Oracles acquisition of Sun)
               cpe = build_cpe(value:jreVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jre:");

               if(isnull(cpe))
                 cpe= "cpe:/a:oracle:jre";

            }

            ## register the separate CPE for 64 apps on 64 bit OS  
            if(jreVer[1] != NULL && "x64" >< osArch && "Wow6432Node" >!< jreKey)
            {
               set_kb_item(name:"Sun/Java64/JRE64/Win/Ver", value:jreVer[1]);
               if(version_is_less(version:jrVer, test_version:"1.4.2.38") ||
                  version_in_range(version:jrVer, test_version:"1.5", test_version2:"1.5.0.33") ||
                  version_in_range(version:jrVer, test_version:"1.6", test_version2:"1.6.0.18"))
               {
                  java_name = "Sun Java JRE 64-bit";
                  ## set the CPE "cpe:/a:sun:jre:" if JRE belongs the above version range
                  ## (Before Oracles acquisition of Sun)
                  ## build cpe and store it as host_detail
                  cpe = build_cpe(value:jreVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jre:x64:");
                  if(isnull(cpe))
                    cpe="cpe:/a:sun:jre:x64";

               }
               else
               {
                  java_name = "Oracle Java JRE 64-bit";
                  ## set the CPE "cpe:/a:oracle:jre:" for recent versions of JRE
                  ## (After Oracles acquisition of Sun)
                  cpe = build_cpe(value:jreVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jre:x64:");
                  if(isnull(cpe))
                  cpe= "cpe:/a:oracle:jre:x64";

               }
            }
          ## Register Product and Build Report
          build_report(app:java_name, ver: jreVer[1], cpe: cpe, insloc: path);   
        }
      }
    }
  }
}

# Java Development Kit
jdkKey = "SOFTWARE\JavaSoft\Java Development Kit";

if("x86" >< osArch){
adkeylist = make_list("SOFTWARE\JavaSoft\Java Development Kit");
}

## Check for 64 bit platform
else if("x64" >< osArch)
{
  adkeylist =  make_list("SOFTWARE\JavaSoft\Java Development Kit",
                         "SOFTWARE\Wow6432Node\JavaSoft\Java Development Kit");
}

foreach jdkKey (adkeylist)
{
  if(registry_key_exists(key:jdkKey))
  {
    keys = registry_enum_keys(key:jdkKey);
    foreach item (keys)
    {
       jdkVer = eregmatch(pattern:"([0-9.]\.[0-9]\.[0-9._]+)", string:item);
       if(jdkVer[1])
       {
          JdkTmpkey =  jdkKey + "\\"  + jdkVer[1];
          if(!registry_key_exists(key:JdkTmpkey)){
            path = "Could not find the install path from registry";
          }
          else
          {
            path = registry_get_sz(key:JdkTmpkey, item:"JavaHome");
            if(!path){
             path = "Could not find the install path from registry";
            }
          }
       
       if(jdkVer[1] != NULL)
       {
         set_kb_item(name:"Sun/Java/JDK/Win/Ver", value:jdkVer[1]);
         replace_kb_item(name:"Sun/Java/JDK_or_JRE/Win/installed", value:TRUE);
         replace_kb_item(name:"Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value:TRUE);
         jdVer = ereg_replace(pattern:"_|-", string:jdkVer[1], replace: ".");

         jdkVer1 = eregmatch(pattern:"([0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)", string:jdVer);
         jdkVer_or = jdkVer1[1] + ":update_" + jdkVer1[2];

         if(version_is_less(version:jdVer, test_version:"1.4.2.38") ||
            version_in_range(version:jdVer, test_version:"1.5", test_version2:"1.5.0.33") ||
            version_in_range(version:jdVer, test_version:"1.6", test_version2:"1.6.0.18"))
         {
           jdk_name= "Sun Java JDK 32-bit";
           ## set the CPE "cpe:/a:sun:jdk:" if JDK belongs the above version range
           ## (Before Oracles acquisition of Sun)
           ## build cpe and store it as host_detail
           cpe = build_cpe(value:jdkVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jdk:");
           if(isnull(cpe))
             cpe= "cpe:/a:sun:jdk";
         }
         else
         {
           jdk_name= "Oracle Java JDK 32-bit";
           ## set the CPE "cpe:/a:oracle:jdk:" for recent versions of JDK
           ## (After Oracles acquisition of Sun)
           cpe = build_cpe(value:jdkVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jdk:");
           if(isnull(cpe))
               cpe="cpe:/a:oracle:jdk";
         }     

         if(jdkVer[1] != NULL && "x64" >< osArch && "Wow6432Node" >!< jdkKey)
         {
           set_kb_item(name:"Sun/Java64/JDK64/Win/Ver", value:jdkVer[1]);
           jdVer = ereg_replace(pattern:"_|-", string:jdkVer[1], replace: ".");

           jdkVer1 = eregmatch(pattern:"([0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)", string:jdVer);

           jdkVer_or = jdkVer1[1] + ":update_" + jdkVer1[2];

           if(version_is_less(version:jdVer, test_version:"1.4.2.38") ||
              version_in_range(version:jdVer, test_version:"1.5", test_version2:"1.5.0.33") ||
              version_in_range(version:jdVer, test_version:"1.6", test_version2:"1.6.0.18"))
           {
             jdk_name= "Sun Java JDK 64-bit";
             ## set the CPE "cpe:/a:sun:jdk:" if JDK belongs the above version range
             ## (Before Oracles acquisition of Sun)
             ## build cpe and store it as host_detail
             cpe = build_cpe(value:jdkVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jdk:x64:");
             if(isnull(cpe))
               cpe= "cpe:/a:sun:jdk:x64";
           }
           else
           {
             jdk_name= "Oracle Java JDK 64-bit";
             ## set the CPE "cpe:/a:oracle:jdk:" for recent versions of JDK
             ## (After Oracles acquisition of Sun)
             cpe = build_cpe(value:jdkVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jdk:x64:");
             if(isnull(cpe))
               cpe="cpe:/a:oracle:jdk:x64";
            } 
          }
         ## Register Product and Build Report
         build_report(app:jdk_name, ver: jdkVer[1], cpe: cpe, insloc: path);
        }
      }
    }
  }
}
exit(0);
