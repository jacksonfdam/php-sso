# Palestra sobre PHP SSO no Tchê Linux Porto Alegre 2019

## Zentyal - Linux Small Business Server 
[Site](http://www.zentyal.org/)

[Repository](https://github.com/zentyal/zentyal)

### Zentyal no Docker
[Dockerfile](https://github.com/zentyal/zentyal/blob/master/extra/scripts/docker/Dockerfile)

### Apache Directory Studio™
[The Eclipse-based LDAP browser and directory client](https://directory.apache.org/studio/)

SimpleSAMLphp low-level SAML2 PHP library 
[Site](https://www.simplesamlphp.org/)

[Repository]([https://github.com/simplesamlphp/saml2](https://github.com/simplesamlphp/saml2))

### LDAP

Um cliente começa uma sessão de LDAP ligando-se a um servidor LDAP, normalmente pela  porta padrão: *389*, TCP. 

Este envia requisições para o servidor, o qual devolve respostas. As operações básicas são:

-   Bind – autentica e especifica a versão do protocolo LDAP;
-   Search – procura por e/ou recupera entradas dos diretórios;
-   Compare – testa se uma entrada tem determinado valor como atributo;
-   ADD – adiciona uma nova entrada;
-   Delete – apaga uma entrada;
-   Modify – modifica uma entrada;
-   Modify DN – move ou renomeia uma entrada;
-   StartTLS[[1]](https://pt.wikipedia.org/wiki/LDAP#cite_note-1)  – protege a conexão com a  [Transport Layer Security](https://pt.wikipedia.org/wiki/Transport_Layer_Security "Transport Layer Security")  (TLS);
-   Abandon – aborta uma requisição prévia;
-   Extended Operation – operação genérica para definir outras operações;
-   Unbind – fecha a conexão, não o inverso de Bind.

####  LDAP Data Interchange Format
O **Formato de Troca de Dados LDAP**, do [inglês](https://pt.wikipedia.org/wiki/Ingl%C3%AAs "Inglês")  **LDAP Data Interchange Format** (**LDIF**), é um formato de troca de dados em [texto plano](https://pt.wikipedia.org/wiki/Texto_plano "Texto plano") padrão para representar o conteúdo de diretório [LDAP](https://pt.wikipedia.org/wiki/LDAP "LDAP")(Lightweight Directory Access Protocol) e requisições de atualização.[[1]](https://pt.wikipedia.org/wiki/LDAP_Data_Interchange_Format#cite_note-1) LDIF transporta conteúdo de diretório como um conjunto de registros, um registro para cada objeto (ou entrada). Ele representa requisições de atualização, tais como Add, Modify, Delete e Rename, como um conjunto de registros, um registro para cada requisição de atualização.

#### Campos LDIF

 dn: distinguished name

Em português  **nome distinto**, refere-se ao nome que identifica unicamente uma entrada no diretório.[[2]](https://pt.wikipedia.org/wiki/LDAP_Data_Interchange_Format#cite_note-2)

>   dc: domain component

Em português  **componente de domínio**, refere-se a cada componente do domínio. Por exemplo www.google.com seria escrito como DC=www,DC=google,DC=com

>   ou: organizational unit

Em português  **unidade organizacional**, refere-se à unidade organizacional (ou algumas vezes o grupo do usuário) que o usuário faz parte. Se o usuário faz parte de mais de um grupo, você pode especificá-los como, por exemplo, OU= Advogado,OU= Juiz.

>   cn: common name

Em português  **nome comum**, refere-se ao objeto individual (nome da pessoa; sala de reunião; nome de receita; cargo; etc.) para o qual/os quais vocês estiver consultando.

-   `CN`  = nome comum
-   `OU`  = Unidade Organizacional
-   `DC`  = Componente de Domínio

Essas são todas as partes da Especificação de Diretório X.500, que define nós em um diretório LDAP.

Você o lê da direita para a esquerda, o componente mais à direita é a raiz da árvore e o componente mais à esquerda é o nó (ou folha) que você deseja alcançar.

Cada par  `=`  é um critério de pesquisa.

Com sua consulta de exemplo

```default
("CN=Dev-India,OU=Distribution Groups,DC=gp,DC=gl,DC=google,DC=com");

```

Com efeito, a consulta é:

Do  `com`  Domain Component, localize o  `google`  Domain Component e, em seguida, o  `gl`  Domain Component e, em seguida, o  `gp`  Domain Component.

No  `gp`  Domain Component, localize a Unidade Organizacional chamada  `Distribution Groups`  e, em seguida, localize o objeto que possui um nome comum  `Dev-India`.

```default
String  X.500 AttributeType
------------------------------
CN      commonName
L       localityName
ST      stateOrProvinceName
O       organizationName
OU      organizationalUnitName
C       countryName
STREET  streetAddress
DC      domainComponent
UID     userid
```
#### PHP SAML 
[Site](https://github.com/lightSAML/lightSAML)

### PHP LDAP
[Site](https://www.php.net/manual/pt_BR/ldap.examples-basic.php)

```shell
(&(objectClass=user)(sAMAccountName=yourUserName)  
(memberof=CN=YourGroup,OU=Users,DC=YourDomain,DC=com))
```

```php
<?php

//LDAP Bind paramters, need to be a normal AD User account.
$ldap_password = 'AD_Password';
$ldap_username = 'AD_Username@domain.tld';
$ldap_connection = ldap_connect("domain.tld");

if (FALSE === $ldap_connection){
            // Uh-oh, something is wrong...
   echo 'Unable to connect to the ldap server';
}

// We have to set this option for the version of Active Directory we are using.
ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3) or die('Unable to set LDAP protocol version');
ldap_set_option($ldap_connection, LDAP_OPT_REFERRALS, 0); // We need this for doing an LDAP search.

if (TRUE === ldap_bind($ldap_connection, $ldap_username, $ldap_password)){

        //Your domains DN to query
    $ldap_base_dn = 'DC=domain,DC=tld,DC=tld';

        //Get standard users and contacts
    $search_filter = '(|(objectCategory=person)(objectCategory=contact))';

        //Connect to LDAP
    $result = ldap_search($ldap_connection, $ldap_base_dn, $search_filter);

    if (FALSE !== $result){
       $entries = ldap_get_entries($ldap_connection, $result);

        // Uncomment the below if you want to write all entries to debug somethingthing 
        //var_dump($entries);

        //Create a table to display the output 
       echo '<h2>AD User Results</h2></br>';
       echo '<table border = "1"><tr bgcolor="#cccccc"><td>Username</td><td>Last Name</td><td>First Name</td><td>Company</td><td>Department</td><td>Office Phone</td><td>Fax</td><td>Mobile</td><td>DDI</td><td>E-Mail Address</td><td>Home Phone</td></tr>';

        //For each account returned by the search
       for ($x=0; $x<$entries['count']; $x++){

        //
        //Retrieve values from Active Directory
        //

        //Windows Usernaame
           $LDAP_samaccountname = "";

           if (!empty($entries[$x]['samaccountname'][0])) {
               $LDAP_samaccountname = $entries[$x]['samaccountname'][0];
               if ($LDAP_samaccountname == "NULL"){
                   $LDAP_samaccountname= "";
               }
           } else {
        //#There is no samaccountname s0 assume this is an AD contact record so generate a unique username

               $LDAP_uSNCreated = $entries[$x]['usncreated'][0];
               $LDAP_samaccountname= "CONTACT_" . $LDAP_uSNCreated;
           }

        //Last Name
           $LDAP_LastName = "";

           if (!empty($entries[$x]['sn'][0])) {
               $LDAP_LastName = $entries[$x]['sn'][0];
               if ($LDAP_LastName == "NULL"){
                   $LDAP_LastName = "";
               }
           }

        //First Name
           $LDAP_FirstName = "";

           if (!empty($entries[$x]['givenname'][0])) {
               $LDAP_FirstName = $entries[$x]['givenname'][0];
               if ($LDAP_FirstName == "NULL"){
                   $LDAP_FirstName = "";
               }
           }

        //Company
           $LDAP_CompanyName = "";

           if (!empty($entries[$x]['company'][0])) {
               $LDAP_CompanyName = $entries[$x]['company'][0];
               if ($LDAP_CompanyName == "NULL"){
                   $LDAP_CompanyName = "";
               }
           }

        //Department
           $LDAP_Department = "";

           if (!empty($entries[$x]['department'][0])) {
               $LDAP_Department = $entries[$x]['department'][0];
               if ($LDAP_Department == "NULL"){
                   $LDAP_Department = "";
               }
           }

        //Job Title
           $LDAP_JobTitle = "";

           if (!empty($entries[$x]['title'][0])) {
               $LDAP_JobTitle = $entries[$x]['title'][0];
               if ($LDAP_JobTitle == "NULL"){
                   $LDAP_JobTitle = "";
               }
           }

        //IPPhone
           $LDAP_OfficePhone = "";

           if (!empty($entries[$x]['ipphone'][0])) {
               $LDAP_OfficePhone = $entries[$x]['ipphone'][0];
               if ($LDAP_OfficePhone == "NULL"){
                   $LDAP_OfficePhone = "";
               }
           }

        //FAX Number
           $LDAP_OfficeFax = "";

           if (!empty($entries[$x]['facsimiletelephonenumber'][0])) {
               $LDAP_OfficeFax = $entries[$x]['facsimiletelephonenumber'][0];
               if ($LDAP_OfficeFax == "NULL"){
                   $LDAP_OfficeFax = "";
               }
           }

        //Mobile Number
           $LDAP_CellPhone = "";

           if (!empty($entries[$x]['mobile'][0])) {
               $LDAP_CellPhone = $entries[$x]['mobile'][0];
               if ($LDAP_CellPhone == "NULL"){
                   $LDAP_CellPhone = "";
               }
           }

        //Telephone Number
           $LDAP_DDI = "";

           if (!empty($entries[$x]['telephonenumber'][0])) {
               $LDAP_DDI = $entries[$x]['telephonenumber'][0];
               if ($LDAP_DDI == "NULL"){
                   $LDAP_DDI = "";
               }
           }

        //Email address
           $LDAP_InternetAddress = "";

           if (!empty($entries[$x]['mail'][0])) {
               $LDAP_InternetAddress = $entries[$x]['mail'][0]; 
               if ($LDAP_InternetAddress == "NULL"){
                   $LDAP_InternetAddress = "";
               }
           }

        //Home phone
           $LDAP_HomePhone = "";

           if (!empty($entries[$x]['homephone'][0])) {
               $LDAP_HomePhone = $entries[$x]['homephone'][0];
               if ($LDAP_HomePhone == "NULL"){
                   $LDAP_HomePhone = "";
               }
           }

           echo "<tr><td><strong>" . $LDAP_samaccountname ."</strong></td><td>" .$LDAP_LastName."</td><td>".$LDAP_FirstName."</td><td>".$LDAP_CompanyName."</td><td>".$LDAP_Department."</td><td>".$LDAP_OfficePhone."</td><td>".$LDAP_OfficeFax."</td><td>".$LDAP_CellPhone."</td><td>".$LDAP_DDI."</td><td>".$LDAP_InternetAddress."</td><td>".$LDAP_HomePhone."</td></tr>";


        } //END for loop
        } //END FALSE !== $result

        ldap_unbind($ldap_connection); // Clean up after ourselves.
        echo("</table>"); //close the table
 
        } //END ldap_bind
?>
```
#### LDAP Authentication & Management for Laravel.
[Packagist](https://packagist.org/packages/adldap2/adldap2-laravel)

[Repository](https://github.com/Adldap2/Adldap2-Laravel)


### Symfony - The Ldap Component
[Site](https://symfony.com/doc/current/components/ldap)

```csv
1.  dn,objectClass,uid,homeDirectory,group,givenName,sn,displayName,cn,mail,manager,telephoneNumber,title
2.  cn=Dan Jump,inetOrgPerson;person;organizationalPerson;posixAccount;top,danj,/home/danj,Executive,Dan,Jump,Dan Jump,Dan Jump,danj@contoso.com,,(425)  555-0179,CEO
3.  cn=Adam Barr,inetOrgPerson;person;organizationalPerson;posixAccount;top,adamb,/home/adamb,Operations,Adam,Barr,Adam Barr,Adam Barr,adamb@contoso.com,cn=Dan Jump,(206)  555-5472,General Manager of Professional Services
```

#### User Data from LDAP
```json
{
  "user": "User [name=My User, roles=[different, groups,…], requestedTenant=null]",
  "user_name": "My User",
  "user_requested_tenant": null,
  "remote_address": "[::1]:58196",
  "backend_roles": [
    "different groups",
    "Linux-Group"
  ],
  "custom_attribute_names": [
    "attr.ldap.msRTCSIP-PrimaryUserAddress",
    "attr.ldap.msTSExpireDate",
    "attr.ldap.logonCount",
    "attr.ldap.lastLogon",
    "attr.ldap.postalCode",
    "attr.ldap.badPwdCount",
    "attr.ldap.userAccountControl",
    "attr.ldap.whenCreated",
    "ldap.original.username",
    "attr.ldap.lastLogoff",
    "attr.ldap.msRTCSIP-FederationEnabled",
    "attr.ldap.l",
    "attr.ldap.sAMAccountName",
    "attr.ldap.msExchTextMessagingState",
    "attr.ldap.userPrincipalName",
    "attr.ldap.msExchUCVoiceMailSettings",
    "attr.ldap.whenChanged",
    "attr.ldap.msRTCSIP-InternetAccessEnabled",
    "attr.ldap.description",
    "attr.ldap.lockoutTime",
    "attr.ldap.displayName",
    "attr.ldap.objectSid",
    "attr.ldap.codePage",
    "attr.ldap.msRTCSIP-Line",
    "attr.ldap.mail",
    "attr.ldap.msExchUMDtmfMap",
    "attr.ldap.lastLogonTimestamp",
    "attr.ldap.primaryGroupID",
    "attr.ldap.msExchMailboxGuid",
    "attr.ldap.objectGUID",
    "attr.ldap.msTSLicenseVersion3",
    "attr.ldap.msTSLicenseVersion2",
    "attr.ldap.msRTCSIP-UserPolicies",
    "attr.ldap.company",
    "attr.ldap.msExchProvisioningFlags",
    "attr.ldap.countryCode",
    "attr.ldap.department",
    "attr.ldap.msExchRemoteRecipientType",
    "attr.ldap.instanceType",
    "attr.ldap.msRTCSIP-UserEnabled",
    "attr.ldap.telephoneNumber",
    "attr.ldap.msTSManagingLS",
    "attr.ldap.objectClass",
    "attr.ldap.msExchVersion",
    "attr.ldap.msExchUMEnabledFlags2",
    "attr.ldap.givenName",
    "attr.ldap.msRTCSIP-DeploymentLocator",
    "attr.ldap.msRTCSIP-OptionFlags",
    "ldap.dn",
    "attr.ldap.sAMAccountType",
    "[attr.ldap.co](http://attr.ldap.co/)",
    "[attr.ldap.cn](http://attr.ldap.cn/)",
    "attr.ldap.msExchMobileBlockedDeviceIDs",
    "attr.ldap.accountExpires",
    "attr.ldap.msExchMobileMailboxFlags",
    "attr.ldap.dSCorePropagationData",
    "attr.ldap.name",
    "attr.ldap.c",
    "attr.ldap.uSNCreated",
    "attr.ldap.uSNChanged",
    "attr.ldap.msExchRecipientTypeDetails",
    "attr.ldap.streetAddress",
    "attr.ldap.pwdLastSet",
    "attr.ldap.msExchUserAccountControl",
    "attr.ldap.msRTCSIP-UserRoutingGroupId",
    "attr.ldap.msExchRecipientDisplayType",
    "attr.ldap.sn",
    "attr.ldap.msExchWhenMailboxCreated",
    "attr.ldap.mailNickname",
    "attr.ldap.msExchMobileAllowedDeviceIDs",
    "attr.ldap.mobile",
    "attr.ldap.msTSLicenseVersion",
    "attr.ldap.msExchHideFromAddressLists",
    "attr.ldap.st"
  ],
  "roles": [
    "Linux-Group",
    "ROLE_LDAP_ADMIN",
    "own_index"
  ],
  "tenants": {
    "My User": true,
    "global_tenant": true
  },
  "principal": null,
  "peer_certificates": "0",
  "sso_logout_url": null
}
```

### How to integrate Active Directory in PHP Application for SSO
[Site](https://medium.com/@prasoon_98674/how-to-integrate-active-directory-in-php-application-for-sso-22eb62b6b866)

#### LDAP and LDAP Injection/Prevention
[Site](https://www.geeksforgeeks.org/ldap-ldap-injectionprevention/)

[https://www.owasp.org/index.php/LDAP_Injection_Prevention_Cheat_Sheet](https://www.owasp.org/index.php/LDAP_Injection_Prevention_Cheat_Sheet)
  
[https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)  

[http://www.faqs.org/rfcs/rfc2254.html](http://www.faqs.org/rfcs/rfc2254.html)

#### Pacote jasny/sso 

[Repository](https://github.com/jasny/sso):  
O utilizei para gerenciar o SSO Server. Ele é bem completo, simples e bastante utilizado pela comunidade. Existem outros pacotes, inclusive encontrei um para Laravel (que parece ser um fork do jasny/sso), mas optei pelo jasny/sso por ver que há bastante tempo ele vem sendo utilizado e atualizado; pelo fato criador do pacote estar participando do processo de amadurecimento do pacote e participando ativamente das ISSUES. Como se trata de uma parte bem sensível, esse foi o que me deixou mais seguro. Existem outros, mas esse eu achei bem simples e interessante. Optei por ele pela quantidade de utilizações e pelo que vi nas ISSUES.

#### Pacote JWT Auth
[Repository](https://github.com/tymondesigns/jwt-auth):  
o JWT é stateless, um requisito indispensável pra trabalhar com SSO, já que um token não pode sobrescrever o outro, como acontece com a API nativa do Laravel.

#### System for Cross-domain Identity Management

SCIM 2, the open API for managing identities is now complete and published under the IETF.
[Site](http://www.simplecloud.info/)