import{S as Ze,i as et,s as tt,M as Ye,e as o,w as m,b as f,c as _e,f as _,g as r,h as l,m as ke,x as me,N as Ve,O as lt,k as st,P as nt,n as ot,t as z,a as G,o as d,d as he,Q as it,C as ze,p as at,r as J,u as rt}from"./index.16774a3c.js";import{S as dt}from"./SdkTabs.e605f71d.js";function Ge(i,s,n){const a=i.slice();return a[6]=s[n],a}function Je(i,s,n){const a=i.slice();return a[6]=s[n],a}function Ke(i){let s;return{c(){s=o("p"),s.innerHTML="Requires admin <code>Authorization:TOKEN</code> header",_(s,"class","txt-hint txt-sm txt-right")},m(n,a){r(n,s,a)},d(n){n&&d(s)}}}function We(i,s){let n,a=s[6].code+"",w,c,p,u;function C(){return s[5](s[6])}return{key:i,first:null,c(){n=o("button"),w=m(a),c=f(),_(n,"class","tab-item"),J(n,"active",s[2]===s[6].code),this.first=n},m(h,R){r(h,n,R),l(n,w),l(n,c),p||(u=rt(n,"click",C),p=!0)},p(h,R){s=h,R&20&&J(n,"active",s[2]===s[6].code)},d(h){h&&d(n),p=!1,u()}}}function Xe(i,s){let n,a,w,c;return a=new Ye({props:{content:s[6].body}}),{key:i,first:null,c(){n=o("div"),_e(a.$$.fragment),w=f(),_(n,"class","tab-item"),J(n,"active",s[2]===s[6].code),this.first=n},m(p,u){r(p,n,u),ke(a,n,null),l(n,w),c=!0},p(p,u){s=p,(!c||u&20)&&J(n,"active",s[2]===s[6].code)},i(p){c||(z(a.$$.fragment,p),c=!0)},o(p){G(a.$$.fragment,p),c=!1},d(p){p&&d(n),he(a)}}}function ct(i){var Ne,Ue;let s,n,a=i[0].name+"",w,c,p,u,C,h,R,N=i[0].name+"",K,ve,W,g,X,B,Y,$,U,we,j,E,ye,Z,Q=i[0].name+"",ee,$e,te,Ce,le,I,se,M,ne,x,oe,O,ie,Fe,ae,D,re,Re,de,ge,k,Oe,S,De,Pe,Te,ce,Ee,pe,Se,Be,Ie,fe,Me,ue,A,be,P,H,F=[],xe=new Map,Ae,q,y=[],He=new Map,T;g=new dt({props:{js:`
        import PocketBase from 'pocketbase';

        const pb = new PocketBase('${i[3]}');

        ...

        const record = await pb.collection('${(Ne=i[0])==null?void 0:Ne.name}').getOne('RECORD_ID', {
            expand: 'relField1,relField2.subRelField',
        });
    `,dart:`
        import 'package:pocketbase/pocketbase.dart';

        final pb = PocketBase('${i[3]}');

        ...

        final record = await pb.collection('${(Ue=i[0])==null?void 0:Ue.name}').getOne('RECORD_ID',
          'expand': 'relField1,relField2.subRelField',
        );
    `}});let v=i[1]&&Ke();S=new Ye({props:{content:"?expand=relField1,relField2.subRelField"}});let V=i[4];const qe=e=>e[6].code;for(let e=0;e<V.length;e+=1){let t=Je(i,V,e),b=qe(t);xe.set(b,F[e]=We(b,t))}let L=i[4];const Le=e=>e[6].code;for(let e=0;e<L.length;e+=1){let t=Ge(i,L,e),b=Le(t);He.set(b,y[e]=Xe(b,t))}return{c(){s=o("h3"),n=m("View ("),w=m(a),c=m(")"),p=f(),u=o("div"),C=o("p"),h=m("Fetch a single "),R=o("strong"),K=m(N),ve=m(" record."),W=f(),_e(g.$$.fragment),X=f(),B=o("h6"),B.textContent="API details",Y=f(),$=o("div"),U=o("strong"),U.textContent="GET",we=f(),j=o("div"),E=o("p"),ye=m("/api/collections/"),Z=o("strong"),ee=m(Q),$e=m("/records/"),te=o("strong"),te.textContent=":id",Ce=f(),v&&v.c(),le=f(),I=o("div"),I.textContent="Path Parameters",se=f(),M=o("table"),M.innerHTML=`<thead><tr><th>Param</th> 
            <th>Type</th> 
            <th width="60%">Description</th></tr></thead> 
    <tbody><tr><td>id</td> 
            <td><span class="label">String</span></td> 
            <td>ID of the record to view.</td></tr></tbody>`,ne=f(),x=o("div"),x.textContent="Query parameters",oe=f(),O=o("table"),ie=o("thead"),ie.innerHTML=`<tr><th>Param</th> 
            <th>Type</th> 
            <th width="60%">Description</th></tr>`,Fe=f(),ae=o("tbody"),D=o("tr"),re=o("td"),re.textContent="expand",Re=f(),de=o("td"),de.innerHTML='<span class="label">String</span>',ge=f(),k=o("td"),Oe=m(`Auto expand record relations. Ex.:\r
                `),_e(S.$$.fragment),De=m(`\r
                Supports up to 6-levels depth nested relations expansion. `),Pe=o("br"),Te=m(`\r
                The expanded relations will be appended to the record under the\r
                `),ce=o("code"),ce.textContent="expand",Ee=m(" property (eg. "),pe=o("code"),pe.textContent='"expand": {"relField1": {...}, ...}',Se=m(`).\r
                `),Be=o("br"),Ie=m(`\r
                Only the relations to which the request user has permissions to `),fe=o("strong"),fe.textContent="view",Me=m(" will be expanded."),ue=f(),A=o("div"),A.textContent="Responses",be=f(),P=o("div"),H=o("div");for(let e=0;e<F.length;e+=1)F[e].c();Ae=f(),q=o("div");for(let e=0;e<y.length;e+=1)y[e].c();_(s,"class","m-b-sm"),_(u,"class","content txt-lg m-b-sm"),_(B,"class","m-b-xs"),_(U,"class","label label-primary"),_(j,"class","content"),_($,"class","alert alert-info"),_(I,"class","section-title"),_(M,"class","table-compact table-border m-b-base"),_(x,"class","section-title"),_(O,"class","table-compact table-border m-b-base"),_(A,"class","section-title"),_(H,"class","tabs-header compact left"),_(q,"class","tabs-content"),_(P,"class","tabs")},m(e,t){r(e,s,t),l(s,n),l(s,w),l(s,c),r(e,p,t),r(e,u,t),l(u,C),l(C,h),l(C,R),l(R,K),l(C,ve),r(e,W,t),ke(g,e,t),r(e,X,t),r(e,B,t),r(e,Y,t),r(e,$,t),l($,U),l($,we),l($,j),l(j,E),l(E,ye),l(E,Z),l(Z,ee),l(E,$e),l(E,te),l($,Ce),v&&v.m($,null),r(e,le,t),r(e,I,t),r(e,se,t),r(e,M,t),r(e,ne,t),r(e,x,t),r(e,oe,t),r(e,O,t),l(O,ie),l(O,Fe),l(O,ae),l(ae,D),l(D,re),l(D,Re),l(D,de),l(D,ge),l(D,k),l(k,Oe),ke(S,k,null),l(k,De),l(k,Pe),l(k,Te),l(k,ce),l(k,Ee),l(k,pe),l(k,Se),l(k,Be),l(k,Ie),l(k,fe),l(k,Me),r(e,ue,t),r(e,A,t),r(e,be,t),r(e,P,t),l(P,H);for(let b=0;b<F.length;b+=1)F[b].m(H,null);l(P,Ae),l(P,q);for(let b=0;b<y.length;b+=1)y[b].m(q,null);T=!0},p(e,[t]){var je,Qe;(!T||t&1)&&a!==(a=e[0].name+"")&&me(w,a),(!T||t&1)&&N!==(N=e[0].name+"")&&me(K,N);const b={};t&9&&(b.js=`
        import PocketBase from 'pocketbase';

        const pb = new PocketBase('${e[3]}');

        ...

        const record = await pb.collection('${(je=e[0])==null?void 0:je.name}').getOne('RECORD_ID', {
            expand: 'relField1,relField2.subRelField',
        });
    `),t&9&&(b.dart=`
        import 'package:pocketbase/pocketbase.dart';

        final pb = PocketBase('${e[3]}');

        ...

        final record = await pb.collection('${(Qe=e[0])==null?void 0:Qe.name}').getOne('RECORD_ID',
          'expand': 'relField1,relField2.subRelField',
        );
    `),g.$set(b),(!T||t&1)&&Q!==(Q=e[0].name+"")&&me(ee,Q),e[1]?v||(v=Ke(),v.c(),v.m($,null)):v&&(v.d(1),v=null),t&20&&(V=e[4],F=Ve(F,t,qe,1,e,V,xe,H,lt,We,null,Je)),t&20&&(L=e[4],st(),y=Ve(y,t,Le,1,e,L,He,q,nt,Xe,null,Ge),ot())},i(e){if(!T){z(g.$$.fragment,e),z(S.$$.fragment,e);for(let t=0;t<L.length;t+=1)z(y[t]);T=!0}},o(e){G(g.$$.fragment,e),G(S.$$.fragment,e);for(let t=0;t<y.length;t+=1)G(y[t]);T=!1},d(e){e&&d(s),e&&d(p),e&&d(u),e&&d(W),he(g,e),e&&d(X),e&&d(B),e&&d(Y),e&&d($),v&&v.d(),e&&d(le),e&&d(I),e&&d(se),e&&d(M),e&&d(ne),e&&d(x),e&&d(oe),e&&d(O),he(S),e&&d(ue),e&&d(A),e&&d(be),e&&d(P);for(let t=0;t<F.length;t+=1)F[t].d();for(let t=0;t<y.length;t+=1)y[t].d()}}}function pt(i,s,n){let a,w,{collection:c=new it}=s,p=200,u=[];const C=h=>n(2,p=h.code);return i.$$set=h=>{"collection"in h&&n(0,c=h.collection)},i.$$.update=()=>{i.$$.dirty&1&&n(1,a=(c==null?void 0:c.viewRule)===null),i.$$.dirty&3&&c!=null&&c.id&&(u.push({code:200,body:JSON.stringify(ze.dummyCollectionRecord(c),null,2)}),a&&u.push({code:403,body:`
                    {
                      "code": 403,
                      "message": "Only admins can access this action.",
                      "data": {}
                    }
                `}),u.push({code:404,body:`
                {
                  "code": 404,
                  "message": "The requested resource wasn't found.",
                  "data": {}
                }
            `}))},n(3,w=ze.getApiExampleUrl(at.baseUrl)),[c,a,p,w,u,C]}class bt extends Ze{constructor(s){super(),et(this,s,pt,ct,tt,{collection:0})}}export{bt as default};
