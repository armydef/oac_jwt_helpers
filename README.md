# oac_jwt_helpers
JWT helpers for the OAC project

## Usage

### Import the library
```console
const jwtLibFactory = require('@igea/oac_jwt_helpers')
const jwtLib = jwtLibFactory({
    secret: SECRET,
    excludePaths: ['/login'],
    signOptions: { expiresIn: '1h' },
});
```

### Create a token
```console
const token = jwtLib.createToken({ id: 123, role: 'admin' });
```

### Define a middleware
```console
app = express();
app.use(express.json());
app.use(jwtLib.middleware);    
```