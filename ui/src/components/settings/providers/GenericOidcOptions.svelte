<script>
    import Field from "@/components/base/Field.svelte";
    export let key = "";
    export let config = {};
</script>

<div class="section-title">OpenID Connect Endpoints</div>
<div class="grid">
    <div class="col-lg-12">
        <Field class="form-field" name="{key}.authUrl" let:uniqueId required>
            <label for={uniqueId}>Auth URL</label>
            <input type="url" id={uniqueId} bind:value={config.authUrl} />
        </Field>
    </div>
    <div class="col-lg-12">
        <Field class="form-field" name="{key}.tokenUrl" let:uniqueId required>
            <label for={uniqueId}>Token URL</label>
            <input type="url" id={uniqueId} bind:value={config.tokenUrl} />
        </Field>
    </div>
    <div class="col-lg-12">
        <Field class="form-field" name="{key}.userApiUrl" let:uniqueId required>
            <label for={uniqueId}>Userinfo URL</label>
            <input type="url" id={uniqueId} bind:value={config.userApiUrl} />
        </Field>
    </div>
</div>
